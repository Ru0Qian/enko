package com.enko.test.scenario;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class JavaBasicVerifier {
    private static final int[] ENCODED_FLAG = {
            87, 84, 94, 33, 54, 49, 53, 9, 6, 47, 26,
            31, 241, 254, 250, 226, 254, 154, 159, 132, 139, 185,
    };

    public boolean verify(String input) {
        String recovered = recoverFlag();
        return input.equals(recovered)
                && constantTimeSha256(input.getBytes(), recovered.getBytes());
    }

    public String recoverFlag() {
        char[] out = new char[ENCODED_FLAG.length];
        for (int i = 0; i < ENCODED_FLAG.length; i++) {
            out[i] = (char)(ENCODED_FLAG[i] ^ ((0x31 + i * 7) & 0xFF));
        }
        return new String(out);
    }

    public boolean constantTimeSha256(byte[] left, byte[] right) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] a = md.digest(left);
            byte[] b = md.digest(right);
            int diff = a.length ^ b.length;
            int count = Math.min(a.length, b.length);
            for (int i = 0; i < count; i++) {
                diff |= a[i] ^ b[i];
            }
            return diff == 0;
        } catch (NoSuchAlgorithmException e) {
            return false;
        }
    }
}
