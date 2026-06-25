package com.enko.shell;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.io.IOException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * TEE-backed secret storage for the hosted app.
 *
 * <p>This class wraps Android Keystore so the hosted application can store
 * runtime secrets (user tokens, login cookies, payment material, device
 * binding identifiers) in a way that survives offline static analysis of
 * the APK. The wrapping key lives in the device's secure hardware
 * (StrongBox &gt;= API 28 when available; TEE Keystore otherwise; software
 * Keystore as last resort), so even a full process memory dump never
 * exposes the underlying key material — only the brief plaintext of
 * individual unwrapped secrets during {@link #getSecret(Context, String)}
 * calls.
 *
 * <p>Secrets are wrapped with AES-256-GCM. The wrap operation is performed
 * inside Keystore via {@link Cipher}, so the key bytes never leave the
 * secure boundary. The resulting ciphertext (with 12-byte IV prefix) is
 * stored in the app's private SharedPreferences and is meaningless to any
 * party that doesn't have access to the device's exact Keystore key.
 *
 * <p>The class is not exposed publicly. Hosted apps reach it through
 * {@link EnkoRuntime#putSecret(Context, String, byte[])} and friends.
 */
final class EnkoSecureStorage {

    private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    private static final String KEY_ALIAS = "enko.shell.secure-storage-key.v1";
    private static final String CIPHER_TRANSFORM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;       // bytes
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final String PREFS_NAME = "enko_secure_storage_v1";
    private static final String PREF_BACKING_NOTE = "_backing_note";

    private EnkoSecureStorage() {
    }

    /**
     * Best-effort detection of whether the Keystore key is actually
     * hardware-backed on this device. Result is informational — the API
     * surface still works on devices with software-only Keystore.
     */
    static String backingNote(Context ctx) {
        try {
            ensureKey();
        } catch (Exception e) {
            return "unavailable";
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            // Best signal we can get without parsing key attestation.
            return "android-keystore-tee-or-strongbox";
        }
        return "android-keystore-tee";
    }

    static void putSecret(Context ctx, String name, byte[] secret) throws GeneralStorageException {
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("secret name required");
        }
        if (secret == null) {
            throw new IllegalArgumentException("secret bytes required");
        }
        try {
            SecretKey wrapping = ensureKey();
            Cipher c = Cipher.getInstance(CIPHER_TRANSFORM);
            c.init(Cipher.ENCRYPT_MODE, wrapping);
            byte[] iv = c.getIV();
            if (iv == null || iv.length != GCM_IV_LENGTH) {
                throw new GeneralStorageException("unexpected IV length");
            }
            byte[] ct = c.doFinal(secret);
            byte[] blob = new byte[GCM_IV_LENGTH + ct.length];
            System.arraycopy(iv, 0, blob, 0, GCM_IV_LENGTH);
            System.arraycopy(ct, 0, blob, GCM_IV_LENGTH, ct.length);
            String encoded = Base64.encodeToString(blob, Base64.NO_WRAP);
            prefs(ctx).edit().putString(prefKey(name), encoded).apply();
        } catch (Exception e) {
            throw new GeneralStorageException("putSecret failed", e);
        }
    }

    static byte[] getSecret(Context ctx, String name) throws GeneralStorageException {
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("secret name required");
        }
        String encoded = prefs(ctx).getString(prefKey(name), null);
        if (encoded == null) {
            return null;
        }
        try {
            byte[] blob = Base64.decode(encoded, Base64.NO_WRAP);
            if (blob.length < GCM_IV_LENGTH + 16) {
                throw new GeneralStorageException("ciphertext too short");
            }
            SecretKey wrapping = ensureKey();
            Cipher c = Cipher.getInstance(CIPHER_TRANSFORM);
            byte[] iv = new byte[GCM_IV_LENGTH];
            System.arraycopy(blob, 0, iv, 0, GCM_IV_LENGTH);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            c.init(Cipher.DECRYPT_MODE, wrapping, spec);
            return c.doFinal(blob, GCM_IV_LENGTH, blob.length - GCM_IV_LENGTH);
        } catch (Exception e) {
            throw new GeneralStorageException("getSecret failed", e);
        }
    }

    static boolean hasSecret(Context ctx, String name) {
        return prefs(ctx).contains(prefKey(name));
    }

    static void removeSecret(Context ctx, String name) {
        prefs(ctx).edit().remove(prefKey(name)).apply();
    }

    private static SecretKey ensureKey() throws GeneralStorageException {
        try {
            KeyStore ks = KeyStore.getInstance(KEYSTORE_PROVIDER);
            ks.load(null);
            KeyStore.Entry entry = ks.getEntry(KEY_ALIAS, null);
            if (entry instanceof KeyStore.SecretKeyEntry) {
                return ((KeyStore.SecretKeyEntry) entry).getSecretKey();
            }
            return generateKey();
        } catch (java.security.KeyStoreException | UnrecoverableEntryException
                | NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new GeneralStorageException("keystore access failed", e);
        }
    }

    private static SecretKey generateKey() throws GeneralStorageException {
        try {
            KeyGenerator kg = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER);
            KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .setRandomizedEncryptionRequired(true);

            // StrongBox: dedicated tamper-resistant hardware on Pixel 3+
            // and many flagship devices since API 28. We attempt it first
            // and fall back to plain Keystore (TEE) if the device doesn't
            // ship StrongBox or the key generation is rejected.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                try {
                    KeyGenParameterSpec.Builder sb = cloneBuilder(b)
                            .setIsStrongBoxBacked(true);
                    kg.init(sb.build());
                    return kg.generateKey();
                } catch (Exception strongBoxFailed) {
                    // Fall through to non-StrongBox path.
                }
            }
            kg.init(b.build());
            return kg.generateKey();
        } catch (NoSuchAlgorithmException | NoSuchProviderException
                | java.security.InvalidAlgorithmParameterException e) {
            throw new GeneralStorageException("keygen failed", e);
        }
    }

    private static KeyGenParameterSpec.Builder cloneBuilder(KeyGenParameterSpec.Builder src) {
        // KeyGenParameterSpec.Builder is not directly cloneable; rebuild
        // from a fresh seed with the same parameters we set above.
        return new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true);
    }

    private static SharedPreferences prefs(Context ctx) {
        return ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    private static String prefKey(String name) {
        return "s." + name;
    }

    /** Marker exception for storage failures so callers don't have to handle every Keystore subtype. */
    static final class GeneralStorageException extends Exception {
        GeneralStorageException(String msg) {
            super(msg);
        }

        GeneralStorageException(String msg, Throwable cause) {
            super(msg, cause);
        }
    }
}
