package com.enko.test.small;

import android.util.Log;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Flag verification — these methods are designed as VMP/extract targets.
 * Each method contains part of the flag decoding logic.
 * Flag format: flag{...}
 */
public class FlagChecker {
    private static final String TAG = "FlagChecker";

    // ── Flag fragments ─────────────────────────────────────────────────

    private static final byte[] SCRAMBLED_FLAG = {
        (byte)0x9F, 0x1C, 0x61, 0x76, (byte)0xC0, 0x6A, 0x5E, 0x51,
        (byte)0x81, 0x77, 0x20, 0x1D, 0x01, (byte)0xE5, (byte)0xDB, (byte)0x9C,
        0x78, (byte)0x8E, (byte)0xF7, (byte)0xBE, 0x39, (byte)0xFA, (byte)0xD6, (byte)0x99,
        0x73, (byte)0xEB, (byte)0xEB, (byte)0xE6, 0x31, (byte)0xC1, (byte)0xAA, 0x54,
        (byte)0xA4,
    };

    // Derives the XOR key from compile-time constants
    public static byte[] deriveKey() {
        byte[] seed = {0x13, 0x37, 0x42, 0x7A};
        byte[] expanded = new byte[8];
        for (int i = 0; i < 4; i++) {
            expanded[i] = seed[i];
        }
        for (int i = 4; i < 8; i++) {
            expanded[i] = (byte)(seed[i - 4] ^ 0x5A ^ (i * 17));
        }
        return mixKey(expanded);
    }

    // Key mixing via sbox transformation
    public static byte[] mixKey(byte[] input) {
        Log.d(TAG, "mixKey input=" + hex(input));
        byte[] mixed = new byte[input.length];
        int acc = 0;
        for (int i = 0; i < input.length; i++) {
            int v = input[i] & 0xFF;
            v = (v ^ 0x3F) + 0x2D;
            v = (v * 59 + 13) & 0xFF;
            mixed[i] = (byte)v;
            acc ^= v;
        }
        mixed[0] ^= (byte)(acc & 0xFF);
        return mixed;
    }

    private static String hex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }

    // Core descrambling — recovers the flag bytes
    public static byte[] descramble(byte[] scrambled, byte[] key) {
        byte[] result = new byte[scrambled.length];
        for (int i = 0; i < scrambled.length; i++) {
            byte ks = key[i % key.length];
            byte tmp = (byte)(scrambled[i] ^ ((i * 7 + 0x2D) & 0xFF));
            result[i] = (byte)(tmp ^ ks);
        }
        return result;
    }

    // Constant-time SHA-256 comparison
    public static boolean verifyHash(byte[] flag, byte[] expectedHash) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] actual = md.digest(flag);
            if (actual.length != expectedHash.length) return false;
            byte diff = 0;
            for (int i = 0; i < actual.length; i++) {
                diff |= (actual[i] ^ expectedHash[i]);
            }
            return diff == 0;
        } catch (NoSuchAlgorithmException e) {
            return false;
        }
    }

    // Recover the full flag string
    public static String recoverFlag() {
        byte[] key = deriveKey();
        byte[] descrambled = descramble(SCRAMBLED_FLAG, key);
        return new String(descrambled);
    }

    // SHA-256 of the correct flag
    // SHA256("flag{3nk0_h4rd3n1ng_r3v3rs3_2026}")
    public static byte[] expectedFlagHash() {
        return new byte[] {
            0x4C, 0x78, (byte)0x84, (byte)0xCB, 0x0B, 0x2D, (byte)0xA4, 0x65,
            (byte)0xD5, (byte)0xD5, (byte)0xC3, 0x43, 0x50, 0x02, 0x3B, 0x63,
            0x3C, 0x13, (byte)0xA7, 0x27, 0x53, (byte)0xC8, (byte)0x8A, (byte)0x92,
            0x3A, (byte)0xFF, 0x4E, 0x7A, (byte)0xD1, 0x72, (byte)0xEA, (byte)0xC7,
        };
    }
}
