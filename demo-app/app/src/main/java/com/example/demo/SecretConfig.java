package com.example.demo;

/**
 * Internal configuration — DO NOT LEAK.
 */
final class SecretConfig {
    private SecretConfig() {}

    // ---- API credentials ----
    static final String API_KEY          = ObfStrings.API_KEY();
    static final String API_SECRET       = ObfStrings.API_SECRET();
    static final String BACKEND_URL      = ObfStrings.BACKEND_URL();
    static final String WEBSOCKET_URL    = ObfStrings.WEBSOCKET_URL();

    // ---- Encryption ----
    static final String AES_KEY_HEX      = ObfStrings.AES_KEY_HEX();
    static final byte[] AES_IV           = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                            (byte)0x88, (byte)0x99, (byte)0xAA, (byte)0xBB,
                                            (byte)0xCC, (byte)0xDD, (byte)0xEE, (byte)0xFF};

    // ---- License server ----
    static final String LICENSE_SERVER   = ObfStrings.LICENSE_SERVER();
    static final String LICENSE_SALT     = ObfStrings.LICENSE_SALT();
    static final String MASTER_LICENSE   = ObfStrings.MASTER_LICENSE();

    // ---- Feature flags ----
    static final String FLAG_CTF         = ObfStrings.FLAG_CTF();
    static final String FLAG_HIDDEN      = ObfStrings.FLAG_HIDDEN();
    static final int    PREMIUM_MAGIC    = 0xDEAD1337;
}
