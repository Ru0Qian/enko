#ifndef ENKO_GCM_H
#define ENKO_GCM_H

#include <stdint.h>
#include <stddef.h>

/**
 * AES-GCM authenticated decryption.
 *
 * Input format: MAGIC(15) + nonce(12) + ciphertext(N) + tag(16)
 *
 * Returns newly malloc'd plaintext on success (caller must free+wipe),
 * or NULL on failure (bad magic, bad tag, alloc error).
 * *out_len is set to plaintext length on success.
 */
uint8_t *enko_gcm_decrypt(const uint8_t *key, size_t key_len,
                           const uint8_t *input, size_t input_len,
                           size_t *out_len);

/**
 * AES-GCM decryption for encrypted config.
 * Input format: CFG_MAGIC(15) + nonce(12) + ciphertext(N) + tag(16)
 */
uint8_t *enko_gcm_decrypt_cfg(const uint8_t *key, size_t key_len,
                               const uint8_t *input, size_t input_len,
                               size_t *out_len);

#endif
