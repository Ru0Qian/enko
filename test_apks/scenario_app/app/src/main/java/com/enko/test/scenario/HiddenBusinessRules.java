package com.enko.test.scenario;

import android.util.Log;

final class HiddenBusinessRules {
    private static final String TAG = "BusinessRules";

    private HiddenBusinessRules() {
    }

    static boolean accept(String flag, String token, String license, int totalCents) {
        if (flag == null || token == null || license == null) {
            return false;
        }
        if (!license.startsWith("ENKO-BIZ")) {
            return false;
        }
        int folded = stableHash(flag + ":" + license + ":" + totalCents);
        Log.i(TAG, "folded=" + folded + " mod64=" + (folded & 0x3F) + " tokenLen=" + token.length());
        return (folded & 0x3F) == 37 && token.length() == 24;
    }

    static int stableHash(String value) {
        int h = 0x13572468;
        for (int i = 0; i < value.length(); i++) {
            h ^= value.charAt(i) * (i + 17);
            h = Integer.rotateLeft(h, 5) + 0x6D2B79F5;
        }
        return h & 0x7FFFFFFF;
    }
}
