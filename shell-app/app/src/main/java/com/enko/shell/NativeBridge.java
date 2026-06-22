package com.enko.shell;

import android.content.Context;

/**
 * JNI bridge to the native 'agpcore' library.
 *
 * <p>Loading the library triggers {@code JNI_OnLoad} which starts the native
 * anti-debug watchdog (ptrace self + background monitoring thread).
 *
 * <p>All crypto operations execute entirely in native memory — key material
 * never lands on the Java heap as raw bytes.
 */
final class NativeBridge {
    private static volatile boolean sLoaded = false;

    static {
        try {
            System.loadLibrary("agpcore");
            sLoaded = true;
        } catch (UnsatisfiedLinkError e) {
            /* Native lib failed to load. There is NO pure-Java fallback: the
             * runtime is fail-closed. ProxyApplication.installPayload() and
             * every integrity/risk gate throw SecurityException when
             * isAvailable() is false, so the app will not boot without the
             * native core. This is intentional — the payload key, integrity
             * pins and decrypt routines live only in native code. */
            sLoaded = false;
        }
    }

    private NativeBridge() {
    }

    /** Whether the native library loaded successfully. */
    static boolean isAvailable() {
        return sLoaded;
    }

    /**
     * Decrypt AES-GCM payload in native memory.
     *
     * @param encrypted raw encrypted payload (MAGIC + nonce + ciphertext + tag)
     * @param keyHex    hex-encoded AES key (32 or 64 chars)
     * @return decrypted plaintext bytes
     * @throws java.security.GeneralSecurityException on decryption failure
     */
    static native byte[] nativeDecrypt(byte[] encrypted, String keyHex);
    static native byte[] nativeDecryptWithEmbeddedKey(byte[] encrypted);

    /**
     * Decrypt AES-GCM encrypted runtime config in native memory.
     *
     * @param encrypted raw encrypted config (CFG_MAGIC + nonce + ciphertext + tag)
     * @return decrypted plaintext config bytes
     * @throws java.security.GeneralSecurityException on decryption failure
     */
    static native byte[] nativeDecryptConfig(Context context, byte[] encrypted);

    /**
     * Native-layer risk detection.
     *
     * @return bitmask:
     *   bit 0 = tracer/debugger detected,
     *   bit 1 = frida in /proc/self/maps,
     *   bit 2 = timing anomaly (single-step suspected),
     *   bit 3 = inline hook/text tamper detected,
     *   bit 4 = root environment,
     *   bit 5 = emulator environment,
     *   bit 6 = hook framework traces,
     *   bit 7 = anti-dump strong signal detected,
     *   bit 8 = system integrity anomaly
     */
    static native int nativeDetectRisk();

    /**
     * Native risk scoring and block decision.
     *
     * @param riskProfile strict/balanced/compat
     * @param blockPolicy true for block policy, false for log policy
     * @param reasonsCsv comma-separated risk reasons
     * @return int[4] = {score, signalCount, highConfidenceCount, shouldBlock(0/1)}
     */
    static native int[] nativeEvaluateRisk(String riskProfile, boolean blockPolicy, String reasonsCsv);

    /**
     * Deobfuscate the XOR-masked key stored in config.
     *
     * @param obfuscatedHex hex-encoded obfuscated key from enko_runtime.cfg
     * @return hex-encoded real AES key
     */
    static native String nativeDeobfuscateKey(String obfuscatedHex);
    static native byte[] nativeGetConfigIntegrityKey();

    /**
     * Verify APK file integrity via native SHA-256.
     *
     * @param apkPath         filesystem path to the APK
     * @param expectedSha256  64-char uppercase hex SHA-256
     * @return true if hash matches
     */
    static native boolean nativeVerifyApkIntegrity(String apkPath, String expectedSha256);
    static native boolean nativeVerifyShellDex(byte[] dexBytes);
    static native boolean nativeCommitNativeLibsDigest(String digestHex);
    static native boolean nativeCommitTrackedLibDigest(String libName, String digestHex);

    /**
     * Compute SHA-256 of arbitrary data entirely in native memory.
     * Returns 64-char uppercase hex string.
     */
    static native String nativeComputeSha256(byte[] data);

    /**
     * Open a file via raw syscall(openat) in native code.
     * This bypasses Java/libc open hooks that may redirect APK path reads.
     *
     * @param path absolute filesystem path
     * @return raw file descriptor (>=0) on success, -1 on failure
     */
    static native int nativeOpenReadOnly(String path);

    /* ---- Anti-dump ---- */

    /**
     * Re-enforce anti-dump protections (PR_SET_DUMPABLE=0, fork detection, etc.).
     * Called automatically in JNI_OnLoad; exposed for explicit re-enforcement.
     */
    static native void nativeAntiDumpInit();

    /**
     * Mark a native memory region as MADV_DONTDUMP.
     * Typically used on DirectByteBuffer backing memory that holds DEX data.
     *
     * @param address native address (from sun.misc.Unsafe or Buffer.address)
     * @param length  region size in bytes
     */
    static native void nativeMarkNoDump(long address, int length);

    /**
     * Protect a DEX memory region with mprotect(PROT_NONE).
     * Blocks /proc/self/mem reads by external processes after ART has loaded the DEX.
     *
     * @param address native address
     * @param length  region size in bytes
     * @return 0 on success, -1 on error
     */
    static native int nativeProtectDexRegion(long address, int length);

    /**
     * Wipe a native memory region (volatile zero-fill + MADV_DONTNEED).
     * Destroys DEX content that was already loaded by the ClassLoader.
     *
     * @param address native address
     * @param length  region size in bytes
     */
    static native void nativeWipeMemory(long address, int length);

    /**
     * Scan /proc for known dump-tool processes.
     *
     * @return bitmask: bit 0 = dump tool, bit 1 = memory editor,
     *         bit 2 = another process has our maps/mem open,
     *         bit 3 = suspicious self maps/mem fd leak,
     *         bit 4 = coredump_filter not hardened,
     *         bit 5 = weak heuristic process match
     */
    static native int nativeDetectDumpTools();

    /* ---- Method Extraction ---- */

    /**
     * Load and decrypt a method extraction blob.
     *
     * @param blob raw encrypted extraction blob bytes
     * @return 0 on success, -1 on error
     */
    static native int nativeExtractLoad(byte[] blob);

    /**
     * Legacy: restore ALL extracted method insns into DEX DirectByteBuffer memory.
     *
     * @param addresses native addresses of each DirectByteBuffer
     * @param sizes     byte sizes of each DirectByteBuffer
     * @param dexCount  number of DEX buffers
     * @return number of methods restored, or -1 on error
     */
    static native int nativeExtractRestore(long[] addresses, int[] sizes, int dexCount);

    /**
     * Bind DEX DirectByteBuffer addresses for on-demand per-class extraction restore.
     * Must be called after nativeExtractLoad and before any class loading.
     *
     * @param addresses native addresses of each DirectByteBuffer
     * @param sizes     byte sizes of each DirectByteBuffer
     * @param dexCount  number of DEX buffers
     * @return 0 on success, -1 on error
     */
    static native int nativeExtractBindDexBuffers(long[] addresses, int[] sizes, int dexCount);

    /**
     * Restore extracted method insns for a single class (on-demand).
     * Called from EnkoInMemoryDexClassLoader.findClass() before super.
     *
     * @param classDesc DEX type descriptor, e.g. "Lcom/example/Foo;"
     * @return number of methods restored for this class, 0 if none, -1 on error
     */
    static native int nativeExtractRestoreClass(String classDesc);

    /* ---- DEX2C ---- */

    /**
     * Register JNI native methods for all DEX2C-compiled methods.
     * Loads libagpjnix.so via dlopen and calls enko_d2c_init.
     *
     * @param loader ClassLoader that loaded the payload DEX
     * @return number of methods registered, or -1 on error
     */
    static native int nativeD2cRegisterNatives(ClassLoader loader);

    /* ---- VMP ---- */

    /**
     * Load a VMP bytecode blob into the native interpreter.
     *
     * @param blob raw VMP blob bytes (from libvtvm.so)
     * @return 0 on success, -1 on error
     */
    static native int nativeVmpLoad(byte[] blob);

    /**
     * Select payload VMP interpreter core tier before registration.
     *
     * @param tier 0=compat, 1=light, 2=strong
     */
    static native int nativeVmpSetTier(int tier);

    /**
     * Register JNI native methods for all VMP-protected methods.
     * Must be called after the payload ClassLoader is established.
     *
     * @param loader ClassLoader that loaded the payload DEX
     * @return number of methods registered, or -1 on error
     */
    static native int nativeVmpRegisterNatives(ClassLoader loader);

    /**
     * Load shell VMP blob into the separate shell interpreter context.
     * Used for self-protection of the shell DEX critical methods.
     */
    static native int nativeShellVmpLoad(byte[] blob);

    /**
     * Select shell VMP interpreter core tier before registration.
     *
     * @param tier 0=compat, 1=light, 2=strong
     */
    static native int nativeShellVmpSetTier(int tier);

    /**
     * Register JNI native methods for all shell VMP-protected methods.
     *
     * @param loader ClassLoader that loaded the shell classes (app ClassLoader)
     * @return number of methods registered, or -1 on error
     */
    static native int nativeShellVmpRegisterNatives(ClassLoader loader);
}
