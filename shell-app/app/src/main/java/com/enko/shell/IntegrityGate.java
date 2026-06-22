package com.enko.shell;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.os.Build;
import android.util.Log;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Static integrity verification and rollback guard checks.
 *
 * All methods are self-contained and do not rely on ProxyApplication instance state.
 */
public final class IntegrityGate {

    private static final String TAG = "EnkoShell";
    private static final String ROLLBACK_PREF = "enko_guard_state";
    private static final String KEY_MAX_BUILD_EPOCH = "max_build_epoch";
    private static final String KEY_MAX_BUILD_VERSION = "max_build_version";
    private static final String KEY_MAX_BUILD_ID = "max_build_id";
    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    private IntegrityGate() {}

    // ── Identity & signature ──────────────────────────────────────────────

    public static void enforceIdentity(Context context, RuntimeConfig cfg)
            throws Exception {
        if (!cfg.expectedPackageName.isEmpty()
                && !cfg.expectedPackageName.equals(context.getPackageName())) {
            throw new SecurityException("unexpected package name");
        }
        if (!SignatureVerifier.verifyCurrentSign(context, cfg.expectedSignSha256)) {
            throw new SecurityException("signature verification failed");
        }
    }

    // ── Rollback guard ────────────────────────────────────────────────────

    public static void enforceRollbackGuard(Context context, RuntimeConfig cfg) {
        if (cfg == null) {
            return;
        }
        if (cfg.buildEpochSec <= 0L
                && cfg.buildVersionCode <= 0L
                && cfg.buildId.isEmpty()) {
            return;
        }

        long currentVersion = getCurrentPackageVersionCode(context);
        if (cfg.buildVersionCode > 0L
                && currentVersion > 0L
                && cfg.buildVersionCode != currentVersion) {
            throw new SecurityException("build version mismatch");
        }

        SharedPreferences prefs =
                context.getSharedPreferences(ROLLBACK_PREF, Context.MODE_PRIVATE);
        long maxSeenEpoch = prefs.getLong(KEY_MAX_BUILD_EPOCH, 0L);
        long maxSeenVersion = prefs.getLong(KEY_MAX_BUILD_VERSION, 0L);
        String maxSeenBuildId = prefs.getString(KEY_MAX_BUILD_ID, "");

        if (cfg.buildVersionCode > 0L
                && maxSeenVersion > 0L
                && cfg.buildVersionCode < maxSeenVersion) {
            throw new SecurityException("rollback detected (version code)");
        }
        if (cfg.buildEpochSec > 0L && maxSeenEpoch > 0L) {
            if (cfg.buildEpochSec < maxSeenEpoch) {
                throw new SecurityException("rollback detected (epoch)");
            }
            if (cfg.buildEpochSec == maxSeenEpoch) {
                if (cfg.buildVersionCode > 0L
                        && maxSeenVersion > 0L
                        && cfg.buildVersionCode < maxSeenVersion) {
                    throw new SecurityException(
                            "rollback detected (epoch equal, version lower)");
                }
            }
        }
        String nextBuildId = maxSeenBuildId;
        if (cfg.buildId.length() > 0) {
            boolean advancedEpoch = cfg.buildEpochSec > maxSeenEpoch;
            boolean advancedVersion = cfg.buildVersionCode > maxSeenVersion;
            if (nextBuildId.length() == 0 || advancedEpoch || advancedVersion) {
                nextBuildId = cfg.buildId;
            }
        }
        prefs.edit()
                .putLong(KEY_MAX_BUILD_EPOCH,
                        Math.max(cfg.buildEpochSec, maxSeenEpoch))
                .putLong(KEY_MAX_BUILD_VERSION,
                        Math.max(cfg.buildVersionCode, maxSeenVersion))
                .putString(KEY_MAX_BUILD_ID, nextBuildId)
                .apply();
    }

    public static long getCurrentPackageVersionCode(Context context) {
        try {
            PackageInfo pi = context.getPackageManager()
                    .getPackageInfo(context.getPackageName(), 0);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                return pi.getLongVersionCode();
            }
            return (long) pi.versionCode;
        } catch (Throwable ignored) {
            return 0L;
        }
    }

    // ── Shell DEX integrity ───────────────────────────────────────────────

    public static void verifyShellDexIntegrity(ZipFile apkZip, RuntimeConfig cfg) {
        if (!NativeBridge.isAvailable()) {
            throw new SecurityException(
                    "native bridge required for shell integrity check");
        }
        try {
            byte[] shellDex = null;
            ZipEntry entry = apkZip.getEntry("classes.dex");
            if (entry == null) {
                throw new SecurityException("classes.dex not found in APK");
            }
            try (InputStream in = apkZip.getInputStream(entry)) {
                shellDex = PayloadCrypto.readAll(in);
            }
            boolean ok = NativeBridge.nativeVerifyShellDex(shellDex);
            PayloadCrypto.wipe(shellDex);
            if (!ok) {
                throw new SecurityException("shell DEX integrity check failed");
            }
        } catch (SecurityException e) {
            throw e;
        } catch (Throwable t) {
            throw new SecurityException("shell DEX integrity check error", t);
        }
    }

    // ── Native library integrity ──────────────────────────────────────────

    public static void verifyNativeLibsIntegrity(
            ZipFile apkZip,
            List<String> nativeSoEntries,
            RuntimeConfig cfg
    ) {
        try {
            List<String> allNativeEntries = new ArrayList<>();
            List<String> libAppEntries = new ArrayList<>();
            List<String> libFlutterEntries = new ArrayList<>();
            for (String entryName : nativeSoEntries) {
                if (entryName.endsWith("/libvtcfg.so")) {
                    continue;
                }
                allNativeEntries.add(entryName);
                if (entryName.endsWith("/libapp.so")) {
                    libAppEntries.add(entryName);
                }
                if (entryName.endsWith("/libflutter.so")) {
                    libFlutterEntries.add(entryName);
                }
            }
            String actual = computeNativeDigest(apkZip, allNativeEntries);
            if (!NativeBridge.nativeCommitNativeLibsDigest(actual)) {
                throw new SecurityException(
                        "native libs integrity check failed");
            }
            if (cfg != null && !cfg.libAppSha256.isEmpty()) {
                String libAppDigest = computeNativeDigest(apkZip, libAppEntries);
                if (libAppDigest.isEmpty()) {
                    throw new SecurityException(
                            "libapp.so integrity target missing");
                }
                if (!NativeBridge.nativeCommitTrackedLibDigest(
                        "libapp.so", libAppDigest)) {
                    throw new SecurityException(
                            "libapp.so integrity check failed");
                }
            }
            if (cfg != null && !cfg.libFlutterSha256.isEmpty()) {
                String libFlutterDigest = computeNativeDigest(
                        apkZip, libFlutterEntries);
                if (libFlutterDigest.isEmpty()) {
                    throw new SecurityException(
                            "libflutter.so integrity target missing");
                }
                if (!NativeBridge.nativeCommitTrackedLibDigest(
                        "libflutter.so", libFlutterDigest)) {
                    throw new SecurityException(
                            "libflutter.so integrity check failed");
                }
            }
        } catch (SecurityException e) {
            throw e;
        } catch (Throwable t) {
            throw new SecurityException("native libs integrity check error", t);
        }
    }

    public static String computeNativeDigest(
            ZipFile apkZip, List<String> entryNames) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] buf = new byte[8192];
        int seen = 0;
        for (String entryName : entryNames) {
            ZipEntry entry = apkZip.getEntry(entryName);
            if (entry == null) {
                continue;
            }
            seen++;
            try (InputStream in = apkZip.getInputStream(entry)) {
                int n;
                while ((n = in.read(buf)) > 0) {
                    md.update(buf, 0, n);
                }
            }
        }
        if (seen == 0) {
            return "";
        }
        return toUpperHex(md.digest());
    }

    // ── Risk reasons collection (called by NetworkRiskWatchdog) ───────────

    public static void collectNativeRiskReasons(
            RuntimeConfig cfg, List<String> reasons) {
        if (cfg == null || reasons == null || !NativeBridge.isAvailable()) {
            return;
        }
        int nativeFlags = NativeBridge.nativeDetectRisk();
        if ((nativeFlags & 1) != 0) reasons.add("native-tracer-detected");
        if ((nativeFlags & 2) != 0) reasons.add("native-frida-detected");
        if ((nativeFlags & 4) != 0) reasons.add("native-timing-anomaly");
        if ((nativeFlags & 8) != 0) reasons.add("native-inline-hook-detected");
        if (cfg.detectRoot && (nativeFlags & 16) != 0) reasons.add("root-environment");
        if (cfg.detectEmulator && (nativeFlags & 32) != 0) reasons.add("emulator-environment");
        if ((nativeFlags & 64) != 0) reasons.add("hook-framework-detected");
        if ((nativeFlags & 128) != 0) reasons.add("dump-tool-detected");
        if ((nativeFlags & 256) != 0) reasons.add("system-integrity-anomaly");
    }

    // ── Utility ───────────────────────────────────────────────────────────

    public static String toUpperHex(byte[] data) {
        char[] out = new char[data.length * 2];
        int p = 0;
        for (byte b : data) {
            int v = b & 0xFF;
            out[p++] = HEX[v >>> 4];
            out[p++] = HEX[v & 0x0F];
        }
        return new String(out);
    }
}
