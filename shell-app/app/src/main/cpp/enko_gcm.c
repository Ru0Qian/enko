#include "enko_gcm.h"
#include "enko_aes.h"
#include "enko_obfstr.h"
#include <stdlib.h>
#include <string.h>

/* "Q7mP2t9Lx1cV8rK" (len=15) — XOR encrypted */
OBFSTR_DECL(obs_payload_magic, 0x96,0xF0,0xAA,0x97,0xF5,0xB3,0xFE,0x8B,0xBF,0xF6,0xA4,0x91,0xFF,0xB5,0x8C);
/* "R4nD8sW2kZ5yH0f" (len=15) — XOR encrypted */
OBFSTR_DECL(obs_cfg_magic, 0x95,0xF3,0xA9,0x83,0xFF,0xB4,0x90,0xF5,0xAC,0x9D,0xF2,0xBE,0x8F,0xF7,0xA1);
#define MAGIC_LEN 15
#define NONCE_LEN 12
#define TAG_LEN   16

static uint32_t rd_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24)
         | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)
         | (uint32_t)p[3];
}

static uint32_t payload_env_next(uint32_t state) {
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
}

static uint8_t *unwrap_payload_envelope(const uint8_t *input, size_t input_len,
                                        const char *magic, size_t *out_len) {
    *out_len = 0;
    if (!input || input_len < 8) return NULL;

    uint32_t seed = rd_be32(input);
    uint32_t encoded_len = rd_be32(input + 4);
    uint32_t inner_len32 = encoded_len ^ seed ^ 0xA35F9C21u;
    size_t inner_len = (size_t)inner_len32;
    if (inner_len > input_len - 8) return NULL;

    uint8_t *inner = (uint8_t *)malloc(inner_len > 0 ? inner_len : 1);
    if (!inner) return NULL;

    uint32_t state = seed ^ 0xC0DEC0DEu;
    for (size_t i = 0; i < inner_len; i++) {
        state = payload_env_next(state);
        uint8_t mask = (uint8_t)(((state >> ((i & 3u) * 8u)) & 0xFFu)
                ^ (((uint32_t)i * 0x5Du + 0xA7u) & 0xFFu));
        inner[i] = input[i + 8] ^ mask;
    }

    if (inner_len < MAGIC_LEN || memcmp(inner, magic, MAGIC_LEN) != 0) {
        memset(inner, 0, inner_len);
        free(inner);
        return NULL;
    }
    *out_len = inner_len;
    return inner;
}

/* ---- GF(2^128) multiplication for GHASH ---- */
static void ghash_multiply(uint8_t result[16], const uint8_t x[16], const uint8_t h[16]) {
    uint8_t v[16];
    memcpy(v, h, 16);
    memset(result, 0, 16);

    for (int i = 0; i < 128; i++) {
        if ((x[i / 8] >> (7 - (i % 8))) & 1) {
            for (int j = 0; j < 16; j++) result[j] ^= v[j];
        }
        /* v = v >> 1 in GF(2^128) with reduction polynomial */
        uint8_t carry = v[15] & 1;
        for (int j = 15; j > 0; j--) {
            v[j] = (v[j] >> 1) | ((v[j - 1] & 1) << 7);
        }
        v[0] >>= 1;
        if (carry) v[0] ^= 0xe1;  /* x^128 + x^7 + x^2 + x + 1 */
    }
}

/* GHASH: process data blocks through GF(2^128) accumulator. */
static void ghash_update(uint8_t state[16], const uint8_t *data, size_t len, const uint8_t h[16]) {
    uint8_t block[16];
    while (len > 0) {
        size_t chunk = len < 16 ? len : 16;
        memset(block, 0, 16);
        memcpy(block, data, chunk);
        for (int i = 0; i < 16; i++) state[i] ^= block[i];

        uint8_t tmp[16];
        ghash_multiply(tmp, state, h);
        memcpy(state, tmp, 16);

        data += chunk;
        len -= chunk;
    }
}

/* Increment the last 4 bytes of a 16-byte counter (big-endian). */
static void inc32(uint8_t ctr[16]) {
    for (int i = 15; i >= 12; i--) {
        if (++ctr[i] != 0) break;
    }
}

/* Internal: AES-GCM decrypt with configurable magic prefix. */
static uint8_t *gcm_decrypt_impl(const uint8_t *key, size_t key_len,
                                  const char *magic,
                                  const uint8_t *input, size_t input_len,
                                  size_t *out_len) {
    *out_len = 0;

    /* Minimum: MAGIC + nonce + tag (no ciphertext is valid for empty plaintext). */
    size_t min_len = MAGIC_LEN + NONCE_LEN + TAG_LEN;
    if (input_len < min_len) return NULL;

    /* Verify magic. */
    if (memcmp(input, magic, MAGIC_LEN) != 0) return NULL;

    const uint8_t *nonce      = input + MAGIC_LEN;
    size_t ct_len             = input_len - MAGIC_LEN - NONCE_LEN - TAG_LEN;
    const uint8_t *ciphertext = input + MAGIC_LEN + NONCE_LEN;
    const uint8_t *tag        = ciphertext + ct_len;

    /* Init AES context. */
    enko_aes_ctx ctx;
    if (enko_aes_init(&ctx, key, key_len) != 0) return NULL;

    /* Compute H = AES_K(0^128). */
    uint8_t h[16];
    memset(h, 0, 16);
    enko_aes_encrypt_block(&ctx, h);

    /* Build initial counter J0 = nonce || 0x00000001. */
    uint8_t j0[16];
    memset(j0, 0, 16);
    memcpy(j0, nonce, NONCE_LEN);
    j0[15] = 1;

    /* Encrypt J0 for final tag XOR. */
    uint8_t ej0[16];
    memcpy(ej0, j0, 16);
    enko_aes_encrypt_block(&ctx, ej0);

    /* CTR decrypt starting from J0 + 1. */
    uint8_t *plaintext = (uint8_t *)malloc(ct_len > 0 ? ct_len : 1);
    if (!plaintext) return NULL;

    uint8_t ctr[16];
    memcpy(ctr, j0, 16);

    for (size_t off = 0; off < ct_len; off += 16) {
        inc32(ctr);
        uint8_t keystream[16];
        memcpy(keystream, ctr, 16);
        enko_aes_encrypt_block(&ctx, keystream);

        size_t chunk = (ct_len - off) < 16 ? (ct_len - off) : 16;
        for (size_t i = 0; i < chunk; i++) {
            plaintext[off + i] = ciphertext[off + i] ^ keystream[i];
        }
    }

    /* GHASH over AAD (none) and ciphertext to verify tag. */
    uint8_t ghash_state[16];
    memset(ghash_state, 0, 16);

    /* No AAD, so skip AAD processing. */

    /* Process ciphertext. */
    ghash_update(ghash_state, ciphertext, ct_len, h);

    /* Process length block: [len(AAD)*8 || len(C)*8] as two 64-bit big-endian. */
    uint8_t len_block[16];
    memset(len_block, 0, 16);
    uint64_t ct_bits = (uint64_t)ct_len * 8;
    len_block[8]  = (uint8_t)(ct_bits >> 56);
    len_block[9]  = (uint8_t)(ct_bits >> 48);
    len_block[10] = (uint8_t)(ct_bits >> 40);
    len_block[11] = (uint8_t)(ct_bits >> 32);
    len_block[12] = (uint8_t)(ct_bits >> 24);
    len_block[13] = (uint8_t)(ct_bits >> 16);
    len_block[14] = (uint8_t)(ct_bits >> 8);
    len_block[15] = (uint8_t)(ct_bits);
    ghash_update(ghash_state, len_block, 16, h);

    /* Compute expected tag: GHASH ^ E(K, J0). */
    uint8_t computed_tag[16];
    for (int i = 0; i < 16; i++) {
        computed_tag[i] = ghash_state[i] ^ ej0[i];
    }

    /* Constant-time tag comparison. */
    uint8_t diff = 0;
    for (int i = 0; i < TAG_LEN; i++) {
        diff |= computed_tag[i] ^ tag[i];
    }

    /* Wipe sensitive intermediates. */
    memset(&ctx, 0, sizeof(ctx));
    memset(h, 0, 16);
    memset(ej0, 0, 16);
    memset(j0, 0, 16);

    if (diff != 0) {
        memset(plaintext, 0, ct_len);
        free(plaintext);
        return NULL;
    }

    *out_len = ct_len;
    return plaintext;
}

uint8_t *enko_gcm_decrypt(const uint8_t *key, size_t key_len,
                           const uint8_t *input, size_t input_len,
                           size_t *out_len) {
    char magic[MAGIC_LEN + 1];
    obs_payload_magic_dec(magic, MAGIC_LEN);
    uint8_t *inner = NULL;
    size_t inner_len = 0;
    const uint8_t *actual_input = input;
    size_t actual_len = input_len;
    if (!input || input_len < MAGIC_LEN || memcmp(input, magic, MAGIC_LEN) != 0) {
        inner = unwrap_payload_envelope(input, input_len, magic, &inner_len);
        if (!inner) {
            memset(magic, 0, sizeof(magic));
            if (out_len) *out_len = 0;
            return NULL;
        }
        actual_input = inner;
        actual_len = inner_len;
    }
    uint8_t *result = gcm_decrypt_impl(key, key_len, magic, actual_input, actual_len, out_len);
    if (inner) {
        memset(inner, 0, inner_len);
        free(inner);
    }
    memset(magic, 0, sizeof(magic));
    return result;
}

uint8_t *enko_gcm_decrypt_cfg(const uint8_t *key, size_t key_len,
                               const uint8_t *input, size_t input_len,
                               size_t *out_len) {
    char magic[MAGIC_LEN + 1];
    obs_cfg_magic_dec(magic, MAGIC_LEN);
    uint8_t *result = gcm_decrypt_impl(key, key_len, magic, input, input_len, out_len);
    memset(magic, 0, sizeof(magic));
    return result;
}
