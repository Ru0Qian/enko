package com.enko.test.scenario;

import android.content.Context;
import android.content.SharedPreferences;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.MessageDigest;

public final class ResourceScenarioVerifier {
    private final Context context;

    ResourceScenarioVerifier(Context context) {
        this.context = context.getApplicationContext();
    }

    public boolean verify(String input) {
        if (input == null) return false;
        SharedPreferences prefs = context.getSharedPreferences(ScenarioApplication.PREFS, Context.MODE_PRIVATE);
        int launches = Math.max(1, prefs.getInt("launches", 1));
        String recovered = recoverFromResources();
        String salted = stableDigest(recovered + ":" + launches);
        return input.equals(recovered) && salted.length() == 64;
    }

    public String recoverFromResources() {
        try (InputStream in = context.getResources().openRawResource(R.raw.resource_secret)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[64];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
            String raw = new String(out.toByteArray()).trim();
            String[] parts = raw.split(",");
            byte[] decoded = new byte[parts.length];
            for (int i = 0; i < parts.length; i++) {
                int v = Integer.parseInt(parts[i], 16);
                decoded[decoded.length - 1 - i] = (byte)(v ^ 0x55);
            }
            return new String(decoded);
        } catch (Throwable ignored) {
            return "";
        }
    }

    public String stableDigest(String value) {
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
