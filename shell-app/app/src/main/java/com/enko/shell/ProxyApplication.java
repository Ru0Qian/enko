package com.enko.shell;

import android.app.Application;
import android.content.Context;
import android.content.pm.ProviderInfo;
import android.util.Log;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.Adler32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Enko shell Application — orchestrates payload decryption, DEX loading,
 * integrity verification, anti-dump protection, and real Application binding.
 *
 * Delegates to {@link IntegrityGate}, {@link DexProtector}, and
 * {@link ApplicationReplacer} for focused responsibilities.
 */
public class ProxyApplication extends Application {
    private static final String TAG = "EnkoShell";
    private static final long BLOCK_KILL_DELAY_MS = 3500L;
    static final String NATIVE_CFG_NAME = "libvtcfg.so";
    static final String NATIVE_PAYLOAD_NAME = "libvtpl.so";
    static final String NATIVE_VMP_NAME = "libvtvm.so";
    static final String NATIVE_EXTRACT_NAME = "libvtex.so";
    private static final String NATIVE_SHELL_VMP_NAME = "libvtshvm.so";
    private static final String LEGACY_ASSET_CFG = "enko_runtime.cfg";
    private static final String LEGACY_ASSET_PAYLOAD = "original_payload.bin";
    private static final boolean ALLOW_LEGACY_ASSET_FALLBACK = false;

    private Application realApplication;
    private RuntimeConfig runtimeConfig;
    private volatile int blockHitCount;
    private volatile boolean degradedMode;
    private volatile boolean delayedKillScheduled;

    // ── Lifecycle ─────────────────────────────────────────────────────────

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        try {
            RuntimeConfig earlyConfig = loadRuntimeConfig(base);
            this.runtimeConfig = earlyConfig;
            DexProtector.initShellVmp(
                    base, getClassLoader(), earlyConfig.requiresShellVmp(),
                    earlyConfig.vmpTierCode());
            installPayload(base);
        } catch (Throwable t) {
            throw new RuntimeException("failed to install payload dex", t);
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        if (realApplication != null) {
            ApplicationReplacer.replaceApplicationReferences(
                    this, realApplication);
            realApplication.onCreate();
            dbgDumpAppState("after realApplication.onCreate");
        }
        if (runtimeConfig != null) {
            enforceRiskPolicy(this, runtimeConfig, "onCreate");
        }
        DexProtector.sAppCreateDone = true;

        /* Replace the Instrumentation so we observe each step of the
         * Activity launch sequence, narrowing down which call between
         * ProxyApplication.onCreate-end and MainActivity.onCreate-start
         * dereferences a null ContextWrapper.mBase. */
        try {
            Class<?> atC = Class.forName("android.app.ActivityThread");
            Object at = atC.getMethod("currentActivityThread").invoke(null);
            java.lang.reflect.Field instF = atC.getDeclaredField("mInstrumentation");
            instF.setAccessible(true);
            android.app.Instrumentation orig =
                    (android.app.Instrumentation) instF.get(at);
            instF.set(at, new TracingInstrumentation(orig));
            Log.i(TAG, "[dbg] Instrumentation replaced with tracing variant");
        } catch (Throwable t) {
            Log.w(TAG, "[dbg] tracing Instrumentation install failed", t);
        }

        /* Hook every Activity lifecycle event so we can pinpoint which one
         * trips the ContextWrapper.getApplicationInfo segfault. */
        registerActivityLifecycleCallbacks(new ActivityLifecycleCallbacks() {
            @Override
            public void onActivityCreated(android.app.Activity activity, android.os.Bundle bundle) {
                dbgDumpActivityState("onActivityCreated", activity);
            }
            @Override public void onActivityStarted(android.app.Activity a) { dbgDumpActivityState("onActivityStarted", a); }
            @Override public void onActivityResumed(android.app.Activity a) {}
            @Override public void onActivityPaused(android.app.Activity a) {}
            @Override public void onActivityStopped(android.app.Activity a) {}
            @Override public void onActivitySaveInstanceState(android.app.Activity a, android.os.Bundle b) {}
            @Override public void onActivityDestroyed(android.app.Activity a) {}
        });
    }

    private static void dbgDumpAppState(String stage) {
        try {
            android.app.Application init = (android.app.Application) java.lang.Class
                    .forName("android.app.ActivityThread")
                    .getMethod("currentApplication").invoke(null);
            java.lang.reflect.Field mBaseF = android.content.ContextWrapper.class.getDeclaredField("mBase");
            mBaseF.setAccessible(true);
            Object mBase = init == null ? null : mBaseF.get(init);
            Log.i(TAG, "[dbg/" + stage + "] currentApplication="
                    + (init == null ? "<null>" : init.getClass().getName())
                    + " mBase=" + (mBase == null ? "<null>" : mBase.getClass().getName()));
        } catch (Throwable t) {
            Log.w(TAG, "[dbg/" + stage + "] dump failed: " + t);
        }
    }

    private static void dbgDumpActivityState(String evt, android.app.Activity act) {
        try {
            java.lang.reflect.Field mBaseF = android.content.ContextWrapper.class.getDeclaredField("mBase");
            mBaseF.setAccessible(true);
            Object mBase = mBaseF.get(act);
            android.app.Application app = act.getApplication();
            Log.i(TAG, "[dbg/" + evt + "] " + act.getClass().getName()
                    + " mBase=" + (mBase == null ? "<null>" : mBase.getClass().getName())
                    + " getApplication=" + (app == null ? "<null>" : app.getClass().getName()));
        } catch (Throwable t) {
            Log.w(TAG, "[dbg/" + evt + "] failed: " + t);
        }
    }

    // ── Payload installation ──────────────────────────────────────────────

    private static RuntimeConfig loadRuntimeConfig(Context context)
            throws Exception {
        String sourceApk = context.getApplicationInfo().sourceDir;
        try (ZipFile apkZip = new ZipFile(sourceApk)) {
            ApkEntryIndex entryIndex = buildApkEntryIndex(apkZip);
            return loadRuntimeConfig(context, apkZip, entryIndex);
        }
    }

    private static RuntimeConfig loadRuntimeConfig(
            Context context,
            ZipFile apkZip,
            ApkEntryIndex entryIndex
    ) throws Exception {
        byte[] cfgEncrypted = readBlobFromNativeLayer(
                context, apkZip, entryIndex, NATIVE_CFG_NAME,
                LEGACY_ASSET_CFG);
        byte[] cfgRaw = null;
        try {
            cfgRaw = NativeBridge.nativeDecryptConfig(context, cfgEncrypted);
            Map<String, String> cfgMap = PayloadCrypto.readConfig(
                    new ByteArrayInputStream(cfgRaw));
            return RuntimeConfig.fromMap(cfgMap);
        } finally {
            PayloadCrypto.wipe(cfgEncrypted);
            PayloadCrypto.wipe(cfgRaw);
        }
    }

    private void installPayload(Context context) throws Exception {
        long installStartNs = System.nanoTime();
        long stageNs = installStartNs;
        if (!NativeBridge.isAvailable()) {
            throw new SecurityException("native bridge unavailable");
        }
        NativeBridge.nativeAntiDumpInit();
        ensureInitProviderPresent(context);

        String sourceApk = context.getApplicationInfo().sourceDir;
        try (ZipFile apkZip = new ZipFile(sourceApk)) {
            ApkEntryIndex entryIndex = buildApkEntryIndex(apkZip);

            RuntimeConfig cfg = this.runtimeConfig;
            if (cfg == null) {
                cfg = loadRuntimeConfig(context, apkZip, entryIndex);
            }
            this.runtimeConfig = cfg;
            stageNs = logTimingStage("runtime-config", stageNs);

            IntegrityGate.enforceIdentity(context, cfg);
            IntegrityGate.verifyShellDexIntegrity(apkZip, cfg);
            IntegrityGate.verifyNativeLibsIntegrity(
                    apkZip, entryIndex.nativeSoEntries, cfg);
            IntegrityGate.enforceRollbackGuard(context, cfg);
            enforceRiskPolicy(context, cfg, "attach-preload");
            stageNs = logTimingStage("integrity-and-risk-preload", stageNs);

            byte[] encrypted = null;
            byte[] decrypted = null;
            byte[] dexPackage = null;

            try {
                encrypted = readBlobFromNativeLayer(
                        context, apkZip, entryIndex,
                        NATIVE_PAYLOAD_NAME, LEGACY_ASSET_PAYLOAD);
                decrypted = NativeBridge.nativeDecryptWithEmbeddedKey(encrypted);
                PayloadCrypto.wipe(encrypted);
                encrypted = null;

                dexPackage = maybeDecompress(decrypted, cfg.payloadCompression);
                if (dexPackage != decrypted) {
                    PayloadCrypto.wipe(decrypted);
                }
                decrypted = null;

                List<PayloadParser.DexEntry> dexEntries =
                        PayloadParser.parse(dexPackage);
                if (dexEntries.isEmpty()) {
                    throw new IllegalStateException(
                            "payload dex list is empty");
                }
                PayloadCrypto.wipe(dexPackage);
                dexPackage = null;

                android.util.Log.i("EnkoShell",
                        "payload dex entries: count=" + dexEntries.size()
                        + " names=" + dexEntriesNamesAndSizes(dexEntries));
                ByteBuffer[] dexBuffers = toDirectBuffers(dexEntries);
                dexEntries = null;
                stageNs = logTimingStage("payload-decrypt-parse", stageNs);

                for (ByteBuffer buf : dexBuffers) {
                    long addr = DexProtector.getDirectBufferAddress(buf);
                    if (addr != 0) {
                        NativeBridge.nativeMarkNoDump(addr, buf.capacity());
                    }
                }

                /* ---- Method Extraction ---- */
                if (cfg.extractEnabled) {
                    byte[] extractBlob = readBlobFromNativeLayer(
                            context, apkZip, entryIndex,
                            NATIVE_EXTRACT_NAME, null);
                    int loadRc = NativeBridge.nativeExtractLoad(extractBlob);
                    PayloadCrypto.wipe(extractBlob);
                    if (loadRc != 0) {
                        throw new SecurityException(
                                "extract: blob load failed (rc="
                                        + loadRc + ")");
                    }

                    long[] addrs = new long[dexBuffers.length];
                    int[] sizes = new int[dexBuffers.length];
                    for (int i = 0; i < dexBuffers.length; i++) {
                        addrs[i] = DexProtector.getDirectBufferAddress(
                                dexBuffers[i]);
                        sizes[i] = dexBuffers[i].capacity();
                    }

                    if (cfg.extractOnDemand) {
                        int bindRc = NativeBridge.nativeExtractBindDexBuffers(
                                addrs, sizes, dexBuffers.length);
                        if (bindRc != 0) {
                            throw new SecurityException(
                                    "extract: on-demand bind failed (rc="
                                            + bindRc + ")");
                        }
                        Log.i(TAG, "extract: on-demand restore enabled");
                    } else {
                        int restored = NativeBridge.nativeExtractRestore(
                                addrs, sizes, dexBuffers.length);
                        if (restored < 0) {
                            throw new SecurityException(
                                    "extract: bulk restore failed (rc="
                                            + restored + ")");
                        }
                        Log.i(TAG, "extract: bulk restored "
                                + restored + " method(s)");
                    }
                    stageNs = logTimingStage(
                            cfg.extractOnDemand
                                    ? "extract-on-demand-bind"
                                    : "extract-bulk-restore",
                            stageNs);
                }

                /* Refresh DEX header SHA-1 + Adler32 unconditionally before
                 * handing the buffers to InMemoryDexClassLoader: VMP method-
                 * stub patching at packer build time modifies code_item bytes
                 * (replacing real Dalvik bytecode with native-stub branches)
                 * and invalidates the original DEX header checksum. Without
                 * this refresh, ART's openInMemoryDexFile path fails with
                 * "Bad checksum" and silently DROPS the DEX from DexPathList
                 * — leaving any class defined in it (e.g., ContentProvider
                 * classes referenced from AndroidManifest) unfindable, which
                 * surfaces later as a ClassNotFoundException at
                 * installContentProviders time. This silently affected the
                 * extract-on-demand path and any non-extract VMP-only build.
                 * Refreshing here is safe: the buffers are direct memory we
                 * own; ART verifies the checksum once at classloader-open
                 * time, and any subsequent in-place per-class extract restore
                 * does not re-trigger header verification. */
                for (ByteBuffer dexBuffer : dexBuffers) {
                    refreshDexHeader(dexBuffer);
                }

                System.gc();

                ClassLoader payloadLoader =
                        new EnkoInMemoryDexClassLoader(
                                dexBuffers, getClassLoader(),
                                cfg.extractEnabled && cfg.extractOnDemand);
                ApplicationReplacer.replaceAppClassLoader(
                        context, payloadLoader);
                enforceRiskPolicy(context, cfg, "attach-post-loader");
                stageNs = logTimingStage("payload-classloader", stageNs);

                /* ---- DEX2C ---- */
                if (cfg.dex2cEnabled) {
                    try {
                        System.loadLibrary("agpjnix");
                        int d2cRegistered =
                                NativeBridge.nativeD2cRegisterNatives(
                                        payloadLoader);
                        if (d2cRegistered <= 0) {
                            throw new SecurityException(
                                    "DEX2C: no methods registered");
                        }
                        Log.i(TAG, "DEX2C: registered "
                                + d2cRegistered + " native method(s)");
                    } catch (UnsatisfiedLinkError e) {
                        throw new SecurityException(
                                "DEX2C: libagpjnix.so missing", e);
                    } catch (Throwable t) {
                        throw new SecurityException(
                                "DEX2C: registration failed", t);
                    }
                    stageNs = logTimingStage("dex2c-register", stageNs);
                }

                /* ---- VMP ---- */
                if (cfg.vmpEnabled) {
                    try {
                        byte[] vmpBlob = readBlobFromNativeLayer(
                                context, apkZip, entryIndex,
                                NATIVE_VMP_NAME, null);
                        int loadResult =
                                NativeBridge.nativeVmpLoad(vmpBlob);
                        if (loadResult != 0) {
                            throw new SecurityException(
                                    "VMP: blob load failed (rc="
                                            + loadResult + ")");
                        }
                        int tierResult =
                                NativeBridge.nativeVmpSetTier(cfg.vmpTierCode());
                        if (tierResult != 0) {
                            throw new SecurityException(
                                    "VMP: tier select failed (rc="
                                            + tierResult + ")");
                        }
                        int registered =
                                NativeBridge.nativeVmpRegisterNatives(
                                        payloadLoader);
                        if (registered <= 0) {
                            throw new SecurityException(
                                    "VMP: no methods registered");
                        }
                        Log.i(TAG, "VMP: loaded blob, registered "
                                + registered + " method(s), tier="
                                + cfg.vmpVmTier);
                        PayloadCrypto.wipe(vmpBlob);
                    } catch (IOException e) {
                        throw new SecurityException(
                                "VMP: blob missing", e);
                    } catch (SecurityException e) {
                        throw e;
                    } catch (Throwable t) {
                        throw new SecurityException(
                                "VMP: registration failed", t);
                    }
                    stageNs = logTimingStage("vmp-register", stageNs);
                }

                if (!cfg.realApplicationClass.isEmpty()) {
                    realApplication =
                            ApplicationReplacer.bindRealApplication(
                                    payloadLoader,
                                    cfg.realApplicationClass,
                                    getBaseContext());
                    Log.i(TAG, "real Application bound: "
                            + cfg.realApplicationClass);
                } else {
                    Log.i(TAG,
                            "no original application class configured");
                }
                enforceRiskPolicy(context, cfg, "attach-post-bind");
                stageNs = logTimingStage("real-application-bind", stageNs);

                DexProtector.corruptDexHeaders(dexBuffers);
                boolean onDemandActive = cfg.extractEnabled && cfg.extractOnDemand;
                if (cfg.protectDexPages) {
                    // Seal the in-memory DEX pages with mprotect(PROT_NONE).
                    DexProtector.scheduleDexProtect(dexBuffers);
                } else if (!onDemandActive) {
                    // Sealing disabled: actively wipe the source buffers once
                    // ART has finished class loading (complementary, not racing
                    // the seal). Headers are already corrupted above. Skipped
                    // when on-demand extraction still needs the buffers for
                    // lazy class loading.
                    DexProtector.scheduleBufferWipe(dexBuffers);
                }
                // Strict / commercial posture: also clear DexFile cookies to
                // block reflection-based DEX dump. Skipped by default because
                // some ART versions can crash; only opt in for hardened builds.
                // Never clear when on-demand extraction is active — the payload
                // class loader still loads classes lazily and needs the cookie.
                if (!onDemandActive
                        && (cfg.commercialMode
                                || (RuntimeConfig.PROFILE_STRICT.equals(cfg.riskProfile)
                                        && RuntimeConfig.POLICY_BLOCK.equals(cfg.riskPolicy)))) {
                    DexProtector.clearDexFileCookies(payloadLoader);
                }
                DexProtector.cleanCodeCache(context);
                stageNs = logTimingStage("post-load-dex-protect", stageNs);
                logTimingTotal("install-payload", installStartNs, stageNs);

            } finally {
                PayloadCrypto.wipe(encrypted);
                PayloadCrypto.wipe(decrypted);
                if (dexPackage != decrypted) {
                    PayloadCrypto.wipe(dexPackage);
                }
            }
        }
    }

    private static long logTimingStage(String stage, long previousNs) {
        long now = System.nanoTime();
        Log.i(TAG, "timing: " + stage + "="
                + ((now - previousNs) / 1_000_000L) + "ms");
        return now;
    }

    private static void logTimingTotal(
            String operation, long startNs, long endNs) {
        Log.i(TAG, "timing: " + operation + ".total="
                + ((endNs - startNs) / 1_000_000L) + "ms");
    }

    // ── Risk policy enforcement (instance state) ──────────────────────────

    private void enforceRiskPolicy(
            Context context, RuntimeConfig cfg, String stage) {
        if (cfg.isOffPolicy()) return;

        List<String> reasons = new ArrayList<>();
        reasons.addAll(NetworkRiskDetector.detectNetworkRisk(
                context, cfg.blockProxyVpn));

        if (!NativeBridge.isAvailable()) {
            throw new SecurityException("native bridge unavailable");
        }
        IntegrityGate.collectNativeRiskReasons(cfg, reasons);
        reasons.addAll(JavaHookDetector.detect());

        NativeRiskEvaluator.Decision decision;
        try {
            decision = NativeRiskEvaluator.evaluate(cfg, reasons);
        } catch (SecurityException e) {
            reasons.add("native-risk-evaluator-failed");
            decision = new NativeRiskEvaluator.Decision(
                    100, reasons.size(), 1, true);
            Log.e(TAG, "native risk evaluator failed at stage="
                    + stage, e);
        }

        if (reasons.isEmpty()) {
            RiskState.clear();
            NetworkRiskWatchdog.start(context, cfg);
            return;
        }

        String reason = NativeRiskEvaluator.joinReasons(reasons);
        String metrics = "profile=" + cfg.riskProfile
                + ",score=" + decision.score
                + ",high=" + decision.highConfidenceCount;

        // P6-1: graded response matrix. Process termination is only reachable
        // under strict profile / commercial mode; otherwise the worst case is
        // RESTRICT, so real users are not killed by default.
        RiskResponsePolicy.Action action =
                RiskResponsePolicy.decide(cfg, decision);
        RiskState.escalate(action);

        switch (action) {
            case TERMINATE:
                if (shouldTerminateNow(stage, reason, metrics)) {
                    throw new SecurityException(
                            "risk environment detected: " + reason
                                    + " (" + metrics + ",stage="
                                    + stage + ")");
                }
                Log.e(TAG, "risk block deferred: " + reason
                        + " (" + metrics + ",stage=" + stage + ")");
                break;
            case RESTRICT:
                Log.e(TAG, "risk restrict mode active (high-value features limited): "
                        + reason + " (" + metrics + ",stage=" + stage + ")");
                break;
            case CHALLENGE:
                Log.w(TAG, "risk challenge mode active (sensitive ops should re-verify): "
                        + reason + " (" + metrics + ",stage=" + stage + ")");
                break;
            case MONITOR:
            default:
                Log.w(TAG, "risk environment detected (monitor): "
                        + reason + " (" + metrics + ",stage=" + stage + ")");
                break;
        }
        NetworkRiskWatchdog.start(context, cfg);
    }

    private synchronized boolean shouldTerminateNow(
            String stage, String reason, String metrics) {
        blockHitCount++;
        if (blockHitCount > 1) return true;
        enterDegradedMode(stage, reason, metrics);
        scheduleDelayedKill(stage, reason, metrics);
        return false;
    }

    private synchronized void enterDegradedMode(
            String stage, String reason, String metrics) {
        if (degradedMode) return;
        degradedMode = true;
        Log.e(TAG, "entering degraded mode: " + reason
                + " (" + metrics + ",stage=" + stage + ")");
    }

    private synchronized void scheduleDelayedKill(
            final String stage,
            final String reason,
            final String metrics) {
        if (delayedKillScheduled) return;
        delayedKillScheduled = true;

        Thread delayedTerminator = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Thread.sleep(BLOCK_KILL_DELAY_MS);
                } catch (InterruptedException ignored) {}
                Log.e(TAG, "delayed terminate on risk: " + reason
                        + " (" + metrics + ",stage=" + stage + ")");
                android.os.Process.killProcess(
                        android.os.Process.myPid());
                System.exit(10);
                Runtime.getRuntime().halt(10);
            }
        }, "fin-ref-1");
        delayedTerminator.setDaemon(true);
        delayedTerminator.start();
    }

    // ── APK entry index ───────────────────────────────────────────────────

    static final class ApkEntryIndex {
        final Map<String, String> nativeLayerBlobEntries;
        final List<String> nativeSoEntries;

        ApkEntryIndex(
                Map<String, String> nativeLayerBlobEntries,
                List<String> nativeSoEntries) {
            this.nativeLayerBlobEntries = nativeLayerBlobEntries;
            this.nativeSoEntries = nativeSoEntries;
        }
    }

    static ApkEntryIndex buildApkEntryIndex(ZipFile zip) {
        Map<String, String> blobEntries = new HashMap<>();
        List<String> soEntries = new ArrayList<>();
        Enumeration<? extends ZipEntry> entries = zip.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            String name = entry.getName();
            if (name == null
                    || !name.startsWith("lib/")
                    || !name.endsWith(".so")) {
                continue;
            }
            soEntries.add(name);
            int slash = name.lastIndexOf('/');
            if (slash >= 0 && slash + 1 < name.length()) {
                String fileName = name.substring(slash + 1);
                if (!blobEntries.containsKey(fileName)) {
                    blobEntries.put(fileName, name);
                }
            }
        }
        Collections.sort(soEntries);
        return new ApkEntryIndex(blobEntries, soEntries);
    }

    static byte[] readBlobFromNativeLayer(
            Context context,
            ZipFile zip,
            ApkEntryIndex entryIndex,
            String nativeLayerName,
            String legacyAssetName) throws IOException {
        try {
            String entryName =
                    entryIndex.nativeLayerBlobEntries.get(nativeLayerName);
            if (entryName != null) {
                ZipEntry entry = zip.getEntry(entryName);
                if (entry != null) {
                    try (InputStream in = zip.getInputStream(entry)) {
                        return PayloadCrypto.readAll(in);
                    }
                }
            }
            throw new IOException(
                    "native-layer blob not found: " + nativeLayerName);
        } catch (IOException e) {
            if (ALLOW_LEGACY_ASSET_FALLBACK
                    && legacyAssetName != null
                    && !legacyAssetName.isEmpty()) {
                Log.w(TAG,
                        "native-layer load failed, fallback to assets: "
                                + nativeLayerName, e);
                try (InputStream in =
                        context.getAssets().open(legacyAssetName)) {
                    return PayloadCrypto.readAll(in);
                }
            }
            throw e;
        }
    }

    // ── Utility ───────────────────────────────────────────────────────────

    private static byte[] maybeDecompress(
            byte[] payload, String compression) throws Exception {
        if (RuntimeConfig.COMPRESSION_ZLIB.equals(compression)) {
            return PayloadCrypto.inflateZlib(payload);
        }
        return payload;
    }

    private static String dexEntriesNamesAndSizes(List<PayloadParser.DexEntry> es) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < es.size(); i++) {
            if (i > 0) sb.append(", ");
            PayloadParser.DexEntry e = es.get(i);
            sb.append(e.name).append("=").append(e.data != null ? e.data.length : -1);
        }
        sb.append("]");
        return sb.toString();
    }

    private static ByteBuffer[] toDirectBuffers(
            List<PayloadParser.DexEntry> dexEntries) {
        ByteBuffer[] out = new ByteBuffer[dexEntries.size()];
        for (int i = 0; i < dexEntries.size(); i++) {
            byte[] dexBytes = dexEntries.get(i).data;
            ByteBuffer buffer = ByteBuffer.allocateDirect(dexBytes.length);
            buffer.put(dexBytes);
            buffer.flip();
            out[i] = buffer;
            PayloadCrypto.wipe(dexBytes);
        }
        return out;
    }

    private static void refreshDexHeader(ByteBuffer buffer)
            throws Exception {
        if (buffer == null || buffer.capacity() < 32) {
            throw new IllegalArgumentException("invalid dex buffer");
        }

        byte[] chunk = new byte[4096];
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        ByteBuffer sigView = buffer.duplicate();
        sigView.position(32);
        while (sigView.hasRemaining()) {
            int n = Math.min(sigView.remaining(), chunk.length);
            sigView.get(chunk, 0, n);
            sha1.update(chunk, 0, n);
        }
        byte[] signature = sha1.digest();

        ByteBuffer writeSig =
                buffer.duplicate().order(ByteOrder.LITTLE_ENDIAN);
        writeSig.position(12);
        writeSig.put(signature, 0, 20);

        Adler32 adler = new Adler32();
        ByteBuffer chkView = buffer.duplicate();
        chkView.position(12);
        while (chkView.hasRemaining()) {
            int n = Math.min(chkView.remaining(), chunk.length);
            chkView.get(chunk, 0, n);
            adler.update(chunk, 0, n);
        }

        ByteBuffer writeCksum =
                buffer.duplicate().order(ByteOrder.LITTLE_ENDIAN);
        writeCksum.putInt(8, (int) adler.getValue());
    }

    private static void ensureInitProviderPresent(Context context) {
        try {
            String authority =
                    context.getPackageName() + ".enko_init";
            ProviderInfo info = context.getPackageManager()
                    .resolveContentProvider(authority, 0);
            if (info == null) {
                throw new SecurityException("init provider missing");
            }
        } catch (SecurityException e) {
            throw e;
        } catch (Throwable t) {
            throw new SecurityException(
                    "init provider check failed", t);
        }
    }
}
