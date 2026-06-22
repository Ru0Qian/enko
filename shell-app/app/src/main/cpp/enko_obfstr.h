#ifndef ENKO_OBFSTR_H
#define ENKO_OBFSTR_H

/*
 * Compile-time string obfuscation.
 *
 * Strings declared with OBFSTR_DECL are stored XOR-encrypted in the
 * .rodata section.  At runtime, call the _dec() function to decode
 * into a stack buffer.  This prevents `strings` / hex dump from
 * revealing sensitive constants in the shared object.
 *
 * Usage:
 *   OBFSTR_DECL(my_secret, 6, 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF);
 *   // ^ use tools/gen_obfstr.py to produce the encrypted bytes
 *
 *   char buf[7];
 *   my_secret_dec(buf, 6);
 *   // buf now contains the plaintext, NUL-terminated
 *
 * Per-file key diversification:
 *   Define OBFSTR_KEY_LOCAL before including this header to use a
 *   different XOR key for that file.  Generate encrypted bytes with:
 *     python tools/gen_obfstr.py --key 0xAB "my string"
 *
 *   #define OBFSTR_KEY_LOCAL 0xAB
 *   #include "enko_obfstr.h"
 *
 * The XOR key is single-byte for simplicity; the real protection comes
 * from preventing trivial `strings` extraction — a determined attacker
 * with a debugger can still recover them.
 */

#include <stdint.h>
#include <stddef.h>

/* Default key — used when OBFSTR_KEY_LOCAL is not defined. */
#define OBFSTR_KEY_DEFAULT 0xC7

/* Effective key: per-file override or default. */
#ifdef OBFSTR_KEY_LOCAL
  #define OBFSTR_KEY OBFSTR_KEY_LOCAL
#else
  #define OBFSTR_KEY OBFSTR_KEY_DEFAULT
#endif

/*
 * Declare an encrypted string constant.
 *   name   — identifier prefix (generates name_enc[] and name_dec())
 *   ...    — XOR-encrypted byte values
 */
#define OBFSTR_DECL(name, ...)                                             \
    static const uint8_t name##_enc[] = { __VA_ARGS__ };                   \
    static inline void name##_dec(char *out, size_t len) {                 \
        /*                                                                \
         * Keep decode dependent on runtime volatile reads so the compiler \
         * cannot trivially fold encrypted bytes into plaintext literals.  \
         */                                                                \
        volatile uint8_t _dyn = (uint8_t)((uintptr_t)(const void *)out);   \
        for (size_t _i = 0; _i < len; _i++) {                              \
            uint8_t _a = _dyn;                                             \
            uint8_t _b = _dyn;                                             \
            out[_i] = (char)(name##_enc[_i] ^ (uint8_t)(OBFSTR_KEY ^ _a) ^ _b); \
        }                                                                  \
        out[len] = '\0';                                                   \
    }

/*
 * Declare an encrypted string with an explicit per-string key.
 * Allows mixing different keys in the same file.
 *   name   — identifier prefix
 *   key    — XOR key byte used to encrypt these values
 *   ...    — XOR-encrypted byte values
 */
#define OBFSTR_DECL_K(name, key, ...)                                      \
    static const uint8_t name##_enc[] = { __VA_ARGS__ };                   \
    static inline void name##_dec(char *out, size_t len) {                 \
        volatile uint8_t _dyn = (uint8_t)((uintptr_t)(const void *)out);   \
        for (size_t _i = 0; _i < len; _i++) {                              \
            uint8_t _a = _dyn;                                             \
            uint8_t _b = _dyn;                                             \
            out[_i] = (char)(name##_enc[_i] ^ (uint8_t)((key) ^ _a) ^ _b); \
        }                                                                  \
        out[len] = '\0';                                                   \
    }

/*
 * Convenience: decrypt into a stack VLA and assign to a local pointer.
 *   varname — local variable name (will be char[])
 *   name    — OBFSTR_DECL identifier
 *   len     — plaintext length (excluding NUL)
 */
#define OBFSTR_USE(varname, name, len)                                  \
    char varname[(len) + 1];                                            \
    name##_dec(varname, (len))

#endif /* ENKO_OBFSTR_H */
