#ifndef ENKO_INTEGRITY_H
#define ENKO_INTEGRITY_H

#include <stdint.h>
#include <stddef.h>

/* ---- Minimal SHA-256 ---- */

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
} enko_sha256_ctx;

void enko_sha256_init(enko_sha256_ctx *ctx);
void enko_sha256_update(enko_sha256_ctx *ctx, const uint8_t *data, size_t len);
void enko_sha256_final(enko_sha256_ctx *ctx, uint8_t digest[32]);

/** One-shot SHA-256. */
void enko_sha256(const uint8_t *data, size_t len, uint8_t digest[32]);

/* ---- APK integrity ---- */

/**
 * Compute SHA-256 of the APK file at `path`.
 * On success writes 32 bytes to `digest` and returns 0.
 * Returns -1 on I/O error.
 */
int enko_apk_sha256(const char *path, uint8_t digest[32]);

/**
 * Verify APK integrity.
 * `path`: filesystem path to the APK.
 * `expected_hex`: 64-char uppercase hex SHA-256.
 * Returns 1 on match, 0 on mismatch, -1 on error.
 */
int enko_verify_apk_integrity(const char *path, const char *expected_hex);

#endif
