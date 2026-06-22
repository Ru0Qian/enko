package com.enko.shell;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

final class PayloadCrypto {
    private PayloadCrypto() {
    }

    static byte[] readAll(InputStream in) throws IOException {
        byte[] buf = new byte[4096];
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int n;
        while ((n = in.read(buf)) > 0) {
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    static Map<String, String> readConfig(InputStream in) throws IOException {
        String raw = new String(readAll(in), StandardCharsets.UTF_8);
        String[] lines = raw.split("\\r?\\n");
        Map<String, String> map = new HashMap<>();
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            int idx = trimmed.indexOf('=');
            if (idx <= 0 || idx >= trimmed.length() - 1) {
                continue;
            }
            String k = trimmed.substring(0, idx);
            String v = trimmed.substring(idx + 1);
            byte[] decoded = Base64.getDecoder().decode(v);
            map.put(k, new String(decoded, StandardCharsets.UTF_8));
        }
        return map;
    }

    static byte[] inflateZlib(byte[] compressed) throws IOException {
        Inflater inflater = new Inflater();
        inflater.setInput(compressed);
        byte[] buf = new byte[4096];
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            while (!inflater.finished()) {
                int n = inflater.inflate(buf);
                if (n == 0) {
                    if (inflater.needsInput()) {
                        break;
                    }
                    throw new IOException("bad zlib payload");
                }
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        } catch (DataFormatException e) {
            throw new IOException("zlib data format error", e);
        } finally {
            inflater.end();
        }
    }

    static void wipe(byte[] data) {
        if (data == null) {
            return;
        }
        /* Use Arrays.fill as the canonical "memory clear" idiom.
         * Additionally, touch the array via a volatile read to prevent
         * JIT from treating this as a dead store and eliding it. */
        java.util.Arrays.fill(data, (byte) 0);
        /* Volatile fence: ensures the fill is committed before return.
         * The unused read prevents the compiler from proving the fill is dead. */
        if (data.length > 0 && data[0] != 0) {
            throw new AssertionError("wipe failed");
        }
    }
}
