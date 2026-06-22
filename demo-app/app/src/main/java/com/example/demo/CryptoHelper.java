package com.example.demo;

import android.util.Base64;
import android.util.Log;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

final class CryptoHelper {
    private static final String TAG = "CryptoHelper";
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";

    private final SecretKeySpec keySpec;
    private final IvParameterSpec ivSpec;

    CryptoHelper() {
        byte[] key = hexToBytes(SecretConfig.AES_KEY_HEX);
        keySpec = new SecretKeySpec(key, "AES");
        ivSpec = new IvParameterSpec(SecretConfig.AES_IV);
    }

    String encrypt(String plaintext) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            byte[] encrypted = cipher.doFinal(plaintext.getBytes("UTF-8"));
            return Base64.encodeToString(encrypted, Base64.NO_WRAP);
        } catch (Exception e) {
            Log.e(TAG, "encrypt failed", e);
            return null;
        }
    }

    String decrypt(String ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            byte[] decoded = Base64.decode(ciphertext, Base64.NO_WRAP);
            byte[] plain = cipher.doFinal(decoded);
            return new String(plain, "UTF-8");
        } catch (Exception e) {
            Log.e(TAG, "decrypt failed", e);
            return null;
        }
    }

    /**
     * Encrypted secret message stored in the app.
     * Decrypting this reveals the hidden flag.
     */
    static final String ENCRYPTED_FLAG = ObfStrings.ENCRYPTED_FLAG();

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                + Character.digit(hex.charAt(i + 1), 16));
        }
        return out;
    }
}
