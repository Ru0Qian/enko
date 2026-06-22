#ifndef ENKO_AES_H
#define ENKO_AES_H

#include <stdint.h>
#include <stddef.h>

#define AES_BLOCK_SIZE 16
#define AES_MAX_ROUNDS 14
#define AES_MAX_EXPANDED 240  /* 4 * (AES_MAX_ROUNDS+1) * 4 */

typedef struct {
    uint32_t rk[AES_MAX_EXPANDED / 4 + 1];
    int nr;  /* number of rounds: 10, 12, or 14 */
} enko_aes_ctx;

/* key_len must be 16 (AES-128) or 32 (AES-256). */
int enko_aes_init(enko_aes_ctx *ctx, const uint8_t *key, size_t key_len);

/* Encrypt a single 16-byte block in-place. */
void enko_aes_encrypt_block(const enko_aes_ctx *ctx, uint8_t block[AES_BLOCK_SIZE]);

#endif
