package com.enko.test.scenario;

import android.content.Context;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

public final class ResourceLicense {
    String readLicense(Context context) {
        try (InputStream in = context.getResources().openRawResource(R.raw.business_license)) {
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
                decoded[decoded.length - 1 - i] = (byte)(v ^ 0x6A);
            }
            return new String(decoded);
        } catch (Throwable ignored) {
            return "";
        }
    }

    boolean verifyLicense(String license) {
        return "ENKO-BIZ-LICENSE-2026".equals(license);
    }
}
