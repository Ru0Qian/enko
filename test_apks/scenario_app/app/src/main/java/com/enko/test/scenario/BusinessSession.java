package com.enko.test.scenario;

import android.content.Context;
import android.provider.Settings;

import java.security.MessageDigest;

public final class BusinessSession {
    String issueToken(Context context, String accountId, String flag) {
        String androidId = Settings.Secure.getString(
                context.getContentResolver(),
                Settings.Secure.ANDROID_ID);
        if (androidId == null || androidId.length() == 0) {
            androidId = "no-device-id";
        }
        String payload = accountId + ":" + context.getPackageName() + ":" + flag.length() + ":" + androidId.length();
        return sha256(payload).substring(0, 24);
    }

    boolean isFresh(String token) {
        if (token == null || token.length() != 24) {
            return false;
        }
        int score = 0;
        for (int i = 0; i < token.length(); i++) {
            char c = token.charAt(i);
            if (c >= '0' && c <= '9') {
                score += c - '0';
            } else if (c >= 'a' && c <= 'f') {
                score += 10 + c - 'a';
            } else {
                return false;
            }
        }
        return score > 30;
    }

    static String sha256(String value) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(value.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b & 0xFF));
            }
            return sb.toString();
        } catch (Throwable ignored) {
            return "";
        }
    }
}
