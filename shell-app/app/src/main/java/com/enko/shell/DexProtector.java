package com.enko.shell;

import android.content.Context;
import android.util.Log;
import java.io.File;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Anti-dump and DEX memory protection utilities.
 *
 * All methods are static and self-contained.  Called from ProxyApplication
 * during payload installation.
 */
public final class DexProtector {

    private static final String TAG = "EnkoShell";
    private static final int CORRUPT_HEADER_BYTES = 256;
    private static final java.util.Random sRng = new java.security.SecureRandom();

    /** Set after realApplication.onCreate() completes — signals class loading is done. */
    static volatile boolean sAppCreateDone;

    private static final Field BUFFER_ADDRESS_FIELD =
            resolveDirectBufferAddressField();

    private DexProtector() {}

    // ── Shell VMP self-protection ─────────────────────────────────────────

    /**
     * Load and register shell VMP blob (self-protection of critical shell methods).
     * Must run before installPayload since installPayload itself may be VMP-protected.
     * In lab builds this is compatibility-friendly. In production posture
     * callers can mark it required so a missing/broken shell VM fails closed.
     */
    public static void initShellVmp(
            Context context, ClassLoader appLoader, boolean required, int vmTier) {
        if (!NativeBridge.isAvailable()) {
            if (required) {
                throw new SecurityException("shell VMP: native bridge unavailable");
            }
            return;
        }
        try {
            String apkPath = context.getApplicationInfo().sourceDir;
            java.util.zip.ZipFile zip = new java.util.zip.ZipFile(apkPath);
            try {
                ProxyApplication.ApkEntryIndex idx =
                        ProxyApplication.buildApkEntryIndex(zip);
                byte[] shellVmpBlob;
                try {
                    shellVmpBlob = ProxyApplication.readBlobFromNativeLayer(
                            context, zip, idx, "libvtshvm.so", null);
                } catch (java.io.IOException ignored) {
                    if (required) {
                        throw new SecurityException("shell VMP: blob missing");
                    }
                    return;
                }
                int loadResult = NativeBridge.nativeShellVmpLoad(shellVmpBlob);
                PayloadCrypto.wipe(shellVmpBlob);
                if (loadResult != 0) {
                    if (required) {
                        throw new SecurityException(
                                "shell VMP: blob load failed (rc="
                                        + loadResult + ")");
                    }
                    Log.w(TAG, "shell VMP: blob load failed (rc=" + loadResult + ")");
                    return;
                }
                int tierResult = NativeBridge.nativeShellVmpSetTier(vmTier);
                if (tierResult != 0 && required) {
                    throw new SecurityException(
                            "shell VMP: tier select failed (rc="
                                    + tierResult + ")");
                }
                int registered =
                        NativeBridge.nativeShellVmpRegisterNatives(appLoader);
                if (registered > 0) {
                    Log.i(TAG, "shell VMP: registered " + registered
                            + " method(s), tier=" + vmTier);
                } else if (required) {
                    throw new SecurityException("shell VMP: no methods registered");
                } else {
                    Log.w(TAG, "shell VMP: no methods registered");
                }
            } finally {
                zip.close();
            }
        } catch (Throwable t) {
            if (required) {
                throw new SecurityException("shell VMP: init failed", t);
            }
            Log.w(TAG, "shell VMP: init failed (non-fatal)", t);
        }
    }

    // ── Direct buffer address ─────────────────────────────────────────────

    private static Field resolveDirectBufferAddressField() {
        try {
            Field addressField =
                    java.nio.Buffer.class.getDeclaredField("address");
            addressField.setAccessible(true);
            return addressField;
        } catch (Throwable ignored) {
            return null;
        }
    }

    public static long getDirectBufferAddress(ByteBuffer buf) {
        if (BUFFER_ADDRESS_FIELD == null) return 0;
        try {
            return BUFFER_ADDRESS_FIELD.getLong(buf);
        } catch (Throwable ignored) {
            return 0;
        }
    }

    // ── DEX header corruption ─────────────────────────────────────────────

    /**
     * Overwrite first 256 bytes of each buffer with random data.
     * ART has already internalised the DEX structures; the source
     * buffer header is only used by dump tools scanning memory.
     * Random fill makes it harder to detect/undo than zero-ing.
     */
    public static void corruptDexHeaders(ByteBuffer[] buffers) {
        byte[] noise = new byte[CORRUPT_HEADER_BYTES];
        for (ByteBuffer buf : buffers) {
            if (buf.capacity() >= CORRUPT_HEADER_BYTES) {
                sRng.nextBytes(noise);
                buf.position(0);
                buf.put(noise);
                buf.position(0);
            }
        }
    }

    // ── Scheduled protection ──────────────────────────────────────────────

    /**
     * Schedule a full wipe of all DirectByteBuffers using active monitoring.
     *
     * <p>Unlike a fixed delay, this waits for {@link #sAppCreateDone} (set after
     * the real Application.onCreate completes — i.e. ART has finished defining
     * and the app is running), then forces a GC so ART's background
     * verifier/compiler has finished with the source buffers, before wiping.
     * Falls back to a hard 30s ceiling so a stuck startup still gets wiped.
     *
     * <p>Only intended to run when DEX-page sealing is disabled
     * ({@code protectDexPages=false}); when sealing is on the pages are made
     * PROT_NONE which already blocks reads, and wiping would race the seal.
     */
    public static void scheduleBufferWipe(final ByteBuffer[] buffers) {
        Thread wiper = new Thread(new Runnable() {
            @Override
            public void run() {
                long waitStart = System.nanoTime();
                long maxWaitNs = 30_000_000_000L; // 30s ceiling
                while (!sAppCreateDone) {
                    long elapsed = System.nanoTime() - waitStart;
                    if (elapsed >= maxWaitNs) break;
                    try {
                        Thread.sleep(200);
                    } catch (InterruptedException ignored) {
                        break;
                    }
                }
                // Give ART's background verifier/JIT a chance to release the
                // source buffers before we destroy them.
                System.gc();
                try {
                    Thread.sleep(1500);
                } catch (InterruptedException ignored) {}
                System.gc();

                int wiped = 0;
                for (ByteBuffer buf : buffers) {
                    if (NativeBridge.isAvailable()) {
                        long addr = getDirectBufferAddress(buf);
                        if (addr != 0) {
                            NativeBridge.nativeWipeMemory(addr, buf.capacity());
                            wiped++;
                        }
                    } else {
                        buf.position(0);
                        byte[] zeros = new byte[Math.min(buf.capacity(), 4096)];
                        int remaining = buf.capacity();
                        while (remaining > 0) {
                            int chunk = Math.min(remaining, zeros.length);
                            buf.put(zeros, 0, chunk);
                            remaining -= chunk;
                        }
                        wiped++;
                    }
                }
                Log.i(TAG, "DEX buffers wiped: " + wiped + "/" + buffers.length);
            }
        }, "pool-sched-2");
        wiper.setDaemon(true);
        wiper.start();
    }

    /**
     * Schedule mprotect(PROT_NONE) on DEX buffer regions after a delay.
     * ART's JIT continues accessing DEX bytecode after class loading, so
     * we wait long enough for JIT compilation to complete before sealing.
     */
    public static void scheduleDexProtect(final ByteBuffer[] buffers) {
        if (!NativeBridge.isAvailable()) return;
        Thread protector = new Thread(new Runnable() {
            @Override
            public void run() {
                long waitStart = System.nanoTime();
                long maxWaitNs = 5_000_000_000L;
                while (!sAppCreateDone) {
                    long elapsed = System.nanoTime() - waitStart;
                    if (elapsed >= maxWaitNs) break;
                    try {
                        Thread.sleep(200);
                    } catch (InterruptedException ignored) {
                        break;
                    }
                }
                try {
                    Thread.sleep(3000);
                } catch (InterruptedException ignored) {}
                int protected_count = 0;
                for (ByteBuffer buf : buffers) {
                    long addr = getDirectBufferAddress(buf);
                    if (addr != 0) {
                        int rc = NativeBridge.nativeProtectDexRegion(
                                addr, buf.capacity());
                        if (rc == 0) protected_count++;
                    }
                }
                Log.i(TAG, "DEX regions sealed: "
                        + protected_count + "/" + buffers.length);
            }
        }, "pool-sched-1");
        protector.setDaemon(true);
        protector.start();
    }

    // ── Code cache cleanup ─────────────────────────────────────────────────

    /**
     * Delete code_cache contents.  InMemoryDexClassLoader on some Android
     * versions writes OAT/VDEX files here that contain the full DEX.
     */
    public static void cleanCodeCache(Context context) {
        try {
            File codeCache = new File(context.getDataDir(), "code_cache");
            if (codeCache.exists()) {
                deleteRecursive(codeCache, false);
            }
        } catch (Throwable ignored) {}
    }

    private static void deleteRecursive(File dir, boolean deleteSelf) {
        if (dir.isDirectory()) {
            File[] children = dir.listFiles();
            if (children != null) {
                for (File child : children) {
                    deleteRecursive(child, true);
                }
            }
        }
        if (deleteSelf) dir.delete();
    }

    // ── DexFile cookie clearing ───────────────────────────────────────────

    /**
     * Clear DexFile.mCookie / mInternalCookie fields to block reflection-based
     * DEX dump (via DexPathList → dexElements → DexFile → mCookie).
     */
    public static void clearDexFileCookies(ClassLoader loader) {
        try {
            Field pathListField = loader.getClass().getSuperclass()
                    .getDeclaredField("pathList");
            pathListField.setAccessible(true);
            Object pathList = pathListField.get(loader);
            if (pathList == null) return;

            Field dexElementsField = pathList.getClass()
                    .getDeclaredField("dexElements");
            dexElementsField.setAccessible(true);
            Object[] dexElements =
                    (Object[]) dexElementsField.get(pathList);
            if (dexElements == null) return;

            for (Object element : dexElements) {
                if (element == null) continue;
                try {
                    Field dexFileField = element.getClass()
                            .getDeclaredField("dexFile");
                    dexFileField.setAccessible(true);
                    Object dexFile = dexFileField.get(element);
                    if (dexFile == null) continue;

                    for (String fieldName :
                            new String[]{"mCookie", "mInternalCookie"}) {
                        try {
                            Field cookieField = dexFile.getClass()
                                    .getDeclaredField(fieldName);
                            cookieField.setAccessible(true);
                            Object cookie = cookieField.get(dexFile);
                            if (cookie instanceof long[]) {
                                long[] arr = (long[]) cookie;
                                Arrays.fill(arr, 0L);
                            }
                            cookieField.set(dexFile, null);
                        } catch (NoSuchFieldException ignored) {}
                    }
                } catch (Throwable ignored) {}
            }
            Log.i(TAG, "DexFile cookies cleared");
        } catch (Throwable ignored) {}
    }
}
