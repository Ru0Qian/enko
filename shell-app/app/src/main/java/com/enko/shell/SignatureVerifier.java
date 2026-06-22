package com.enko.shell;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.os.Parcelable;
import java.io.FileInputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

final class SignatureVerifier {
    private static final Pattern SIGNATURE_ENTRY =
            Pattern.compile("META-INF/.*\\.(RSA|DSA|EC)");

    private SignatureVerifier() {
    }

    static boolean verifyCurrentSign(Context context, String expectedSha256Hex) throws Exception {
        if (expectedSha256Hex == null || expectedSha256Hex.isEmpty()) {
            return false;
        }

        /*
         * Detect PackageInfo parcel creator tampering (e.g. replacement with an
         * app-defined Creator that rewrites signatures during unmarshalling).
         */
        if (isPackageInfoCreatorTampered()) {
            return false;
        }

        String fromPm = getCurrentSignSha256(context);
        if (!expectedSha256Hex.equalsIgnoreCase(fromPm)) {
            return false;
        }

        /*
         * Cross-check with certificate read from APK file descriptor opened via
         * native syscall(openat), which bypasses common libc open/openat hooks.
         *
         * If no V1 cert entry is present (rare in this pipeline), return empty
         * and keep PM result as fallback.
         */
        String fromApk = getCurrentSignSha256FromApkSyscall(context);
        if (!fromApk.isEmpty()) {
            if (!expectedSha256Hex.equalsIgnoreCase(fromApk)) {
                return false;
            }
            if (!fromPm.equalsIgnoreCase(fromApk)) {
                return false;
            }
        }
        return true;
    }

    static String getCurrentSignSha256(Context context) throws Exception {
        byte[] cert = getAppCertBytesFromPackageManager(context);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(cert);
        return toUpperHex(digest);
    }

    private static String getCurrentSignSha256FromApkSyscall(Context context) throws Exception {
        int fd = NativeBridge.nativeOpenReadOnly(context.getApplicationInfo().sourceDir);
        if (fd < 0) {
            return "";
        }

        byte[] cert = readApkV1CertFromFd(fd);
        if (cert == null || cert.length == 0) {
            return "";
        }

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(cert);
        return toUpperHex(digest);
    }

    private static boolean isPackageInfoCreatorTampered() {
        Parcelable.Creator<PackageInfo> creator = PackageInfo.CREATOR;
        if (creator == null) {
            return true;
        }
        Class<?> creatorClass = creator.getClass();
        String name = creatorClass.getName();
        ClassLoader loader = creatorClass.getClassLoader();
        boolean nameOk = "android.content.pm.PackageInfo$1".equals(name);
        boolean loaderOk = (loader == null)
                || "java.lang.BootClassLoader".equals(loader.getClass().getName());
        return !(nameOk && loaderOk);
    }

    private static byte[] getAppCertBytesFromPackageManager(Context context) throws Exception {
        PackageManager pm = context.getPackageManager();
        String pkg = context.getPackageName();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES);
            if (pi.signingInfo == null) {
                throw new IllegalStateException("signingInfo is null");
            }
            Signature[] signs = pi.signingInfo.hasMultipleSigners()
                    ? pi.signingInfo.getApkContentsSigners()
                    : pi.signingInfo.getSigningCertificateHistory();
            if (signs == null || signs.length == 0) {
                throw new IllegalStateException("no signing certificate found");
            }
            return signs[0].toByteArray();
        }

        PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES);
        if (pi.signatures == null || pi.signatures.length == 0) {
            throw new IllegalStateException("no signature found");
        }
        return pi.signatures[0].toByteArray();
    }

    private static byte[] readApkV1CertFromFd(int fd) throws Exception {
        try (ParcelFileDescriptor pfd = ParcelFileDescriptor.adoptFd(fd);
             ZipInputStream zis = new ZipInputStream(new FileInputStream(pfd.getFileDescriptor()))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName();
                if (name == null || !SIGNATURE_ENTRY.matcher(name).matches()) {
                    continue;
                }
                try {
                    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                    X509Certificate cert = (X509Certificate) certFactory.generateCertificate(zis);
                    return cert.getEncoded();
                } catch (Throwable ignored) {
                    // Some APK signature entries are not directly parseable certificates.
                    // Continue scanning; fallback to PM certificate check if none parse.
                }
            }
        }
        return null;
    }

    private static String toUpperHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(String.format(Locale.US, "%02X", b));
        }
        return sb.toString();
    }
}
