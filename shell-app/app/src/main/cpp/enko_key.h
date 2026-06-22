#ifndef ENKO_KEY_H
#define ENKO_KEY_H

#include <stdint.h>
#include <stddef.h>

#define ENKO_MAX_KEY_LEN 32

/**
 * Recover the real AES key from an XOR-obfuscated seed.
 * seed/seed_len: hex-decoded obfuscated key bytes from cfg.
 * out: buffer of at least seed_len bytes to receive the real key.
 * Returns 0 on success, -1 on error.
 */
int enko_key_deobfuscate(const uint8_t *seed, size_t seed_len,
                          uint8_t *out, size_t out_len);

/** Derive AES-128 key for config encryption from compiled-in XOR mask.
 *  Writes 16 bytes to out. Returns 0 on success. */
int enko_derive_cfg_key(uint8_t out[16]);
/** Derive embedded AES-256 payload key from compiled-in material.
 *  Writes 32 bytes to out. Returns 0 on success. */
int enko_derive_payload_key(uint8_t out[32]);

/**
 * Try to load a per-APK AES-256 payload key patched into libagpcore.so by the packer.
 *
 * On success writes 32 bytes to out and returns 0.
 * Returns <0 if the slot is missing/unpatched or the key check fails.
 */
int enko_get_per_apk_payload_key(uint8_t out[32]);

/**
 * Initialize runtime entropy sources (build-id, stack canary, .text hash).
 * Must be called once on the main thread before any key derivation.
 */
void enko_key_entropy_init(void);

/** Secure wipe. */
void enko_secure_wipe(void *buf, size_t len);

/** Parse hex string to bytes. Returns byte count or -1. */
int enko_hex_decode(const char *hex, size_t hex_len, uint8_t *out, size_t out_max);

#endif
