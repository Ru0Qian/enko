package com.enko.shell;

import android.content.Context;

/**
 * Public, stable runtime API exposed by the Enko shell to the hosted app (P6-1).
 *
 * <p>The shell never reaches into the protected app's code. Instead, the app
 * can <em>query</em> the current graded risk level here and decide how to
 * respond for sensitive flows, without the shell killing the process:
 *
 * <pre>{@code
 *   if (EnkoRuntime.shouldRestrict()) {
 *       // hide / disable high-value features (paid content, asset transfer...)
 *   } else if (EnkoRuntime.shouldChallenge()) {
 *       // require server-side re-verification before login / payment
 *   }
 * }</pre>
 *
 * <p>This is read-only telemetry the app opts into. It complements (does not
 * replace) server-side verification: high-value decisions (auth, payment,
 * membership, assets) must still be confirmed by the backend, with the risk
 * level used as one signal.
 *
 * <p>Kept by proguard ({@code -keep}) so the integration symbol survives R8.
 */
public final class EnkoRuntime {

    private EnkoRuntime() {
    }

    /** Current graded risk level name: ALLOW / MONITOR / CHALLENGE / RESTRICT / TERMINATE. */
    public static String riskLevel() {
        return RiskState.current().name();
    }

    /**
     * Whether the environment is risky enough that sensitive operations
     * (login, payment, license activation) should request server-side
     * re-verification before proceeding.
     */
    public static boolean shouldChallenge() {
        return RiskState.shouldChallenge();
    }

    /**
     * Whether high-value features (paid content, asset transfer, etc.) should
     * be disabled or limited because of elevated runtime risk.
     */
    public static boolean shouldRestrict() {
        return RiskState.shouldRestrict();
    }

    // ────────────────────────────────────────────────────────────────────
    // TEE-backed secret storage (P5-5).
    //
    // Hosted apps can park runtime-generated secrets (user tokens, login
    // cookies, payment material, device-binding identifiers) under a key
    // that lives in the device's secure hardware (StrongBox on API 28+
    // devices that ship it, TEE Keystore elsewhere, software keystore as
    // a final fallback). The wrapping key never leaves the secure
    // boundary, so static analysis of the APK or offline inspection of
    // app-private files cannot recover stored secrets.
    //
    // All methods are exception-free at the API boundary: storage
    // failures (no Keystore, hardware tampering, etc.) surface as a null
    // / false return value. Callers should not depend on this storage
    // for keys whose loss would brick the app — it's a complement to,
    // not a replacement for, server-side secret bootstrap.
    // ────────────────────────────────────────────────────────────────────

    /**
     * Store {@code secret} under {@code name} in TEE-backed storage. The
     * raw bytes are encrypted via Android Keystore before being persisted
     * to the app's private SharedPreferences; the wrapping key never
     * appears in plaintext anywhere outside the secure hardware.
     *
     * @return true if the secret was successfully stored.
     */
    public static boolean putSecret(Context ctx, String name, byte[] secret) {
        if (ctx == null) {
            return false;
        }
        try {
            EnkoSecureStorage.putSecret(ctx, name, secret);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Retrieve and decrypt a previously-stored secret. Returns null if no
     * secret with that name exists, or if decryption failed (e.g. the
     * wrapping key was invalidated by a screen-lock reset on devices with
     * key invalidation, or the Keystore is otherwise unavailable).
     */
    public static byte[] getSecret(Context ctx, String name) {
        if (ctx == null) {
            return null;
        }
        try {
            return EnkoSecureStorage.getSecret(ctx, name);
        } catch (Exception e) {
            return null;
        }
    }

    /** Whether a secret with the given name currently exists in storage. */
    public static boolean hasSecret(Context ctx, String name) {
        if (ctx == null) {
            return false;
        }
        return EnkoSecureStorage.hasSecret(ctx, name);
    }

    /** Remove a secret. No-op if it doesn't exist. */
    public static void removeSecret(Context ctx, String name) {
        if (ctx == null) {
            return;
        }
        EnkoSecureStorage.removeSecret(ctx, name);
    }

    /**
     * Informational backing identifier for the secret-storage subsystem
     * (e.g. {@code "android-keystore-tee-or-strongbox"}). For diagnostics
     * and feature gating: apps that need provable hardware-backed storage
     * can check this string and degrade gracefully on weaker devices.
     */
    public static String secretStorageBacking(Context ctx) {
        if (ctx == null) {
            return "unavailable";
        }
        return EnkoSecureStorage.backingNote(ctx);
    }
}
