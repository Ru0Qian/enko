#ifndef ENKO_EXTRACT_H
#define ENKO_EXTRACT_H

#include <stdint.h>
#include <stddef.h>

/**
 * Load and decrypt a method extraction blob.
 *
 * The blob is AES-GCM encrypted (magic "T9qE1vN6pM3uC7x" + nonce + ct + tag).
 * The payload key is obtained from the per-APK key slot or legacy derivation.
 *
 * @param blob     raw encrypted blob bytes
 * @param blob_len byte length of blob
 * @return 0 on success, <0 on error
 */
int enko_extract_load(const uint8_t *blob, size_t blob_len);

/**
 * Bind the in-memory DEX buffers used by InMemoryDexClassLoader.
 *
 * The extraction runtime keeps these base addresses/sizes so it can restore
 * stubbed method bodies on-demand at class load time.
 *
 * @param dex_addrs  array of native addresses of DirectByteBuffers
 * @param dex_sizes  array of buffer sizes (bytes)
 * @param dex_count  number of DEX buffers
 * @return 0 on success, <0 on error
 */
int enko_extract_bind_dex_buffers(const uintptr_t *dex_addrs, const int32_t *dex_sizes,
                                 int dex_count);

/**
 * Restore extracted method insns for a single class descriptor.
 *
 * Called from a ClassLoader.findClass hook before the class is defined so
 * the verifier sees the original bytecode.
 *
 * @param class_desc DEX type descriptor, e.g. "Lcom/example/Foo;"
 * @return number of methods restored for this class, 0 if none, <0 on error
 */
int enko_extract_restore_class(const char *class_desc);

/**
 * Legacy: restore ALL extracted methods into DEX DirectByteBuffer memory.
 *
 * Kept for debugging/emergency fallback. Production flow should use:
 *   enko_extract_load() + enko_extract_bind_dex_buffers() + enko_extract_restore_class().
 */
int enko_extract_restore(const uintptr_t *dex_addrs, const int32_t *dex_sizes,
                         int dex_count);

/**
 * Securely wipe and free all extraction data.
 */
void enko_extract_free(void);

#endif /* ENKO_EXTRACT_H */
