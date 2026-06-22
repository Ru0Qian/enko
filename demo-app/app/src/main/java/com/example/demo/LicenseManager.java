package com.example.demo;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;
import java.security.MessageDigest;

final class LicenseManager {
    private static final String TAG = "LicenseManager";
    private static final String PREFS_NAME = "enko_license";
    private static final String KEY_LICENSE = "license_key";
    private static final String KEY_ACTIVATED = "activated";

    private final Context context;
    private boolean activated = false;

    LicenseManager(Context context) {
        this.context = context.getApplicationContext();
        loadState();
    }

    private void loadState() {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        activated = prefs.getBoolean(KEY_ACTIVATED, false);
    }

    /**
     * Validate a license key.
     * Format: ENKO-XXXX-YYYY-ZZZZ-WWWW
     * Validation: SHA-256(salt + key_body) first 4 bytes == "enko"
     */
    boolean validateLicense(String key) {
        if (key == null || key.isEmpty()) return false;

        // Master key always passes
        if (SecretConfig.MASTER_LICENSE.equals(key)) {
            activate(key);
            return true;
        }

        // Format check
        if (!key.matches("ENKO-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}")) {
            Log.w(TAG, "invalid license format");
            return false;
        }

        try {
            String body = key.replace("ENKO-", "").replace("-", "");
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(SecretConfig.LICENSE_SALT.getBytes("UTF-8"));
            md.update(body.getBytes("UTF-8"));
            byte[] hash = md.digest();

            // Check: first 4 bytes of hash match magic
            int magic = ((hash[0] & 0xFF) << 24) | ((hash[1] & 0xFF) << 16)
                      | ((hash[2] & 0xFF) << 8) | (hash[3] & 0xFF);

            if (magic == SecretConfig.PREMIUM_MAGIC) {
                activate(key);
                return true;
            }
        } catch (Exception e) {
            Log.e(TAG, "license validation error", e);
        }

        return false;
    }

    private void activate(String key) {
        activated = true;
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        prefs.edit()
             .putString(KEY_LICENSE, key)
             .putBoolean(KEY_ACTIVATED, true)
             .apply();
        Log.i(TAG, "license activated");
    }

    boolean isActivated() {
        return activated;
    }

    String getStatusText() {
        if (activated) {
            return "✅ Premium activated\n" + SecretConfig.FLAG_CTF;
        }
        return "❌ Free version — enter license key to unlock premium features";
    }
}
