package com.example.demo;

import android.content.Context;
import android.util.Log;
import java.security.MessageDigest;

/**
 * Premium features only accessible to licensed users.
 */
final class PremiumFeature {
    private static final String TAG = "PremiumFeature";

    private PremiumFeature() {}

    /**
     * Generate device fingerprint (premium-only).
     */
    static String getDeviceFingerprint(Context context) {
        try {
            String raw = android.os.Build.BRAND + "|"
                       + android.os.Build.MODEL + "|"
                       + android.os.Build.SERIAL + "|"
                       + android.provider.Settings.Secure.getString(
                             context.getContentResolver(),
                             android.provider.Settings.Secure.ANDROID_ID);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(raw.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return "error";
        }
    }

    /**
     * Secret computation that connects to the backend.
     */
    static String callSecretApi(String token) {
        Log.d(TAG, "calling " + SecretConfig.BACKEND_URL + " with token");
        // In a real app, this would make an HTTP request.
        // For demo, just return a simulated response.
        return "{\"status\":\"ok\",\"flag\":\"" + SecretConfig.FLAG_HIDDEN + "\"}";
    }

    /**
     * Decrypt user data using internal key.
     */
    static String decryptUserData(String encrypted) {
        CryptoHelper crypto = new CryptoHelper();
        return crypto.decrypt(encrypted);
    }
}
