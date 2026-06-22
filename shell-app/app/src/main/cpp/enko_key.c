#include "enko_key.h"
#include "enko_integrity.h"
#include "enko_obfstr.h"
#include <string.h>
#include <link.h>
#include <elf.h>

/*
 * Obfuscation mask split into 8 XOR-encoded fragments of 4 bytes each.
 * Each fragment uses a unique compile-time salt.  At runtime, fragments
 * are assembled on the stack with volatile-anchored decoding so the
 * compiler cannot statically fold them back into a single constant.
 *
 * Combined mask (hex):
 *   A3 5C 7E 19 B2 D4 F0 68 3A 91 C5 E7 0B 4D 82 F6
 *   17 8B E3 5A C9 04 76 DF 61 AD 38 F2 4E 85 B0 2C
 */

#define FRAG_SALT0 0x37
#define FRAG_SALT1 0x6D
#define FRAG_SALT2 0xA3
#define FRAG_SALT3 0xD9
#define FRAG_SALT4 0x0F
#define FRAG_SALT5 0x45
#define FRAG_SALT6 0x7B
#define FRAG_SALT7 0xB1

/* XOR-encoded mask fragments — each byte = original ^ fragment_salt */
static const uint8_t M_F0[] = { 0x94, 0x6B, 0x49, 0x2E };
static const uint8_t M_F1[] = { 0xDF, 0xB9, 0x9D, 0x05 };
static const uint8_t M_F2[] = { 0x99, 0x32, 0x66, 0x44 };
static const uint8_t M_F3[] = { 0xD2, 0x94, 0x5B, 0x2F };
static const uint8_t M_F4[] = { 0x18, 0x84, 0xEC, 0x55 };
static const uint8_t M_F5[] = { 0x8C, 0x41, 0x33, 0x9A };
static const uint8_t M_F6[] = { 0x1A, 0xD6, 0x43, 0x89 };
static const uint8_t M_F7[] = { 0xFF, 0x34, 0x01, 0x9D };

/* vtx_payload_key_v2x (len=19) — XOR encrypted */
OBFSTR_DECL(obs_payload_key_seed, 0xB1,0xB3,0xBF,0x98,0xB7,0xA6,0xBE,0xAB,0xA8,0xA6,0xA3,0x98,0xAC,0xA2,0xBE,0x98,0xB1,0xF5,0xBF);

/* ── Runtime entropy: build-id + stack canary + .text hash ──────────── */

static volatile int g_rt_entropy_ready = 0;
static uint8_t g_build_id[20];
static uint64_t g_stack_canary = 0;
static uint8_t g_text_hash[32];

/* Shared callback context for dl_iterate_phdr. */
struct elf_cb_ctx {
    uintptr_t base;
    const ElfW(Phdr) *phdr;
    int phnum;
    int found;
};

static int find_self_callback(struct dl_phdr_info *info, size_t sz, void *data) {
    (void)sz;
    struct elf_cb_ctx *c = (struct elf_cb_ctx *)data;
    uintptr_t fn_addr = (uintptr_t)(const void *)find_self_callback;
    if (!info->dlpi_addr) return 0;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_LOAD) {
            uintptr_t seg_start = info->dlpi_addr + info->dlpi_phdr[i].p_vaddr;
            uintptr_t seg_end = seg_start + info->dlpi_phdr[i].p_memsz;
            if (fn_addr >= seg_start && fn_addr < seg_end) {
                c->base  = info->dlpi_addr;
                c->phdr  = info->dlpi_phdr;
                c->phnum = info->dlpi_phnum;
                c->found = 1;
                return 1;
            }
        }
    }
    return 0;
}

/* Walk ELF notes to find GNU build-id. */
static int get_self_build_id(uint8_t out[20]) {
    struct elf_cb_ctx ctx = { 0, NULL, 0, 0 };
    dl_iterate_phdr(find_self_callback, &ctx);
    if (!ctx.found) return -1;

    const ElfW(Phdr) *phdr = ctx.phdr;
    int phnum = ctx.phnum;
    uintptr_t base = ctx.base;

    /* Walk program headers looking for PT_NOTE. */
    for (int i = 0; i < phnum; i++) {
        if (phdr[i].p_type != PT_NOTE) continue;

        const uint8_t *note_start = (const uint8_t *)(base + phdr[i].p_vaddr);
        const uint8_t *note_end = note_start + phdr[i].p_filesz;

        while (note_start + sizeof(ElfW(Nhdr)) <= note_end) {
            const ElfW(Nhdr) *nhdr = (const ElfW(Nhdr) *)note_start;
            note_start += sizeof(ElfW(Nhdr));
            const char *name = (const char *)note_start;
            size_t name_sz = (size_t)nhdr->n_namesz;
            size_t desc_sz = (size_t)nhdr->n_descsz;

            note_start += (name_sz + 3) & ~3U;
            const uint8_t *desc = note_start;
            note_start += (desc_sz + 3) & ~3U;

            if (nhdr->n_type == NT_GNU_BUILD_ID && name_sz >= 4
                && memcmp(name, "GNU", 4) == 0 && desc_sz >= 20) {
                memcpy(out, desc, 20);
                return 0;
            }
        }
    }
    return -1;
}

/* Read thread-local stack canary (only valid on main thread). */
static uint64_t get_stack_canary(void) {
    uint64_t val = 0;
    extern uintptr_t __stack_chk_guard;
    memcpy(&val, (const void *)&__stack_chk_guard, sizeof(val));
    return val;
}

/* Hash the executable PT_LOAD segment of libagpcore.so. */
static int get_text_hash(uint8_t out[32]) {
    struct elf_cb_ctx ctx = { 0, NULL, 0, 0 };
    dl_iterate_phdr(find_self_callback, &ctx);
    if (!ctx.found) return -1;

    const ElfW(Phdr) *phdr = ctx.phdr;
    int phnum = ctx.phnum;
    uintptr_t base = ctx.base;

    /* Find the first executable PT_LOAD segment. */
    for (int i = 0; i < phnum; i++) {
        if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_X)) {
            const uint8_t *text_start = (const uint8_t *)(base + phdr[i].p_vaddr);
            size_t text_sz = (size_t)phdr[i].p_filesz;
            if (text_sz > 0x100000) text_sz = 0x100000; /* cap at 1 MB */
            enko_sha256(text_start, text_sz, out);
            return 0;
        }
    }
    return -1;
}

/* Initialize runtime entropy sources. Must be called on the main thread
 * before any key derivation. */
void enko_key_entropy_init(void) {
    /* Build-ID — best-effort, may be stripped. */
    if (get_self_build_id(g_build_id) != 0) {
        /* Fallback: SHA-256 of .text base address truncated to 20 bytes. */
        uintptr_t self_addr = (uintptr_t)(const void *)enko_key_entropy_init;
        enko_sha256((const uint8_t *)&self_addr, sizeof(self_addr), g_text_hash);
        memcpy(g_build_id, g_text_hash, 20);
    }

    /* Stack canary — read once on main thread. */
    g_stack_canary = get_stack_canary();
    if (g_stack_canary == 0) {
        /* Extremely unlikely fallback: use address ASLR as entropy. */
        uintptr_t sp = (uintptr_t)&sp;
        g_stack_canary = (uint64_t)sp ^ ((uint64_t)sp << 32);
    }

    /* .text hash — hash executable segment for integrity-sensitive entropy. */
    if (get_text_hash(g_text_hash) != 0) {
        /* Fallback: repeat self-address hash. */
        uintptr_t self_addr = (uintptr_t)(const void *)enko_key_entropy_init;
        enko_sha256((const uint8_t *)&self_addr, sizeof(self_addr), g_text_hash);
    }

    g_rt_entropy_ready = 1;
}

/*
 * Per-APK payload key slot.
 *
 * The packer patches these bytes inside libagpcore.so for each hardened APK.
 * The comparison constants (HEAD/TAIL) are XOR-encoded and decoded at runtime;
 * the in-blob markers remain raw so the packer can still locate the slot via
 * binary search.
 */

#define HSALT 0x5A  /* HEAD marker XOR salt (compile-time fallback) */
#define TSALT 0xA5  /* TAIL marker XOR salt (compile-time fallback) */

#define ENKO_PERAPK_MAGIC_LEN 16
#define ENKO_PERAPK_KEY_LEN   32
#define ENKO_PERAPK_CHECK_LEN 32
#define ENKO_PERAPK_ANCHOR_LEN 8

/* XOR-encoded slot marker constants (compile-time fallback only —
 * at runtime the actual markers are read from ENKO_MARKER_STORE
 * which the packer fills with per-APK random values). */
static const uint8_t ENKO_PERAPK_HEAD_ENC[ENKO_PERAPK_MAGIC_LEN] = {
    0x89,0xCB,0x30,0x74,0xED,0x16,0xA2,0x4F,
    0xC0,0x39,0x9B,0x27,0xBE,0x78,0x01,0xCA
};
static const uint8_t ENKO_PERAPK_TAIL_ENC[ENKO_PERAPK_MAGIC_LEN] = {
    0x2B,0xE2,0x17,0xBC,0xF9,0x75,0xD6,0x03,
    0x54,0x98,0x21,0x8F,0x6C,0xCB,0xB4,0x50
};

/*
 * Per-APK marker store.
 *
 * Layout: [8-byte anchor magic] [16-byte head marker] [16-byte tail marker]
 * The packer generates random head/tail per APK, patches them here, AND
 * patches the same values into ENKO_PERAPK_KEY_BLOB.
 *
 * At runtime we read the markers from this store to know what to expect
 * in the blob — no static marker survives across builds.
 */
__attribute__((used))
static volatile const uint8_t ENKO_MARKER_STORE[] = {
    /* anchor magic — must match PER_APK_MARKER_STORE_ANCHOR in packer */
    0xE7,0x3A,0x91,0x5C,0xD2,0x8F,0x46,0xB0,
    /* head marker (patched by packer with per-APK random bytes) */
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    /* tail marker (patched by packer with per-APK random bytes) */
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
};
#define ENKO_MARKER_STORE_HEAD_OFF  ENKO_PERAPK_ANCHOR_LEN
#define ENKO_MARKER_STORE_TAIL_OFF  (ENKO_PERAPK_ANCHOR_LEN + ENKO_PERAPK_MAGIC_LEN)

/*
 * volatile: the packer patches SLOT and CHECK at build time, so the compiler
 * must NOT assume the initial zero values are final.
 */
__attribute__((used, retain))
static volatile const uint8_t ENKO_PERAPK_KEY_BLOB[] = {
    /* head marker (patched by packer with per-APK random bytes) */
    0xD3,0x91,0x6A,0x2E,0xB7,0x4C,0xF8,0x15,0x9A,0x63,0xC1,0x7D,0xE4,0x22,0x5B,0x90,

    /* SLOT (patched by packer) */
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,

    /* CHECK = SHA-256(K) (patched by packer) */
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,

    /* tail marker (patched by packer with per-APK random bytes) */
    0x8E,0x47,0xB2,0x19,0x5C,0xD0,0x73,0xA6,0xF1,0x3D,0x84,0x2A,0xC9,0x6E,0x11,0xF5,
};

/* Dummy volatile pointer to prevent linker from GC'ing the blob.
 * __attribute__((used)) is not always enough with -fdata-sections --gc-sections
 * when the only references are per-byte reads in a for-loop. */
__attribute__((used))
static volatile const uint8_t *const _ENKO_PERAPK_KEY_BLOB_ANCHOR =
    (const uint8_t *)ENKO_PERAPK_KEY_BLOB;

/*
 * Decode a single mask fragment into out[0..3].
 * Volatile-anchored: enc[i] ^ (salt ^ a) ^ b  where a,b are
 * separate reads of the same volatile — the compiler cannot
 * statically prove a==b and therefore cannot fold to a constant.
 */
static void decode_frag(const uint8_t enc[4], uint8_t salt, uint8_t out[4]) {
    volatile uint8_t _dyn = (uint8_t)((uintptr_t)(const void *)out);
    for (int i = 0; i < 4; i++) {
        uint8_t a = _dyn, b = _dyn;
        out[i] = enc[i] ^ (uint8_t)(salt ^ a) ^ b;
    }
}

__attribute__((annotate("fla"), annotate("sub")))
static void build_mask(uint8_t mask[ENKO_MAX_KEY_LEN], int with_entropy) {
    decode_frag(M_F0, FRAG_SALT0, mask);
    decode_frag(M_F1, FRAG_SALT1, mask + 4);
    decode_frag(M_F2, FRAG_SALT2, mask + 8);
    decode_frag(M_F3, FRAG_SALT3, mask + 12);
    decode_frag(M_F4, FRAG_SALT4, mask + 16);
    decode_frag(M_F5, FRAG_SALT5, mask + 20);
    decode_frag(M_F6, FRAG_SALT6, mask + 24);
    decode_frag(M_F7, FRAG_SALT7, mask + 28);

    if (with_entropy && g_rt_entropy_ready) {
        /* XOR runtime entropy into the mask: build-id (20) +
         * stack canary (8) + .text hash prefix (4) = 32 bytes. */
        uint8_t rt_entropy[ENKO_MAX_KEY_LEN];
        memcpy(rt_entropy,       g_build_id,       20);
        memcpy(rt_entropy + 20, &g_stack_canary,   8);
        memcpy(rt_entropy + 28,  g_text_hash,      4);

        for (int i = 0; i < ENKO_MAX_KEY_LEN; i++) {
            mask[i] ^= rt_entropy[i];
        }
        enko_secure_wipe(rt_entropy, sizeof(rt_entropy));
    }
}

/* Decode a marker into a stack buffer. */
static void decode_perapk_marker(const uint8_t enc[ENKO_PERAPK_MAGIC_LEN],
                                  uint8_t salt,
                                  uint8_t out[ENKO_PERAPK_MAGIC_LEN]) {
    volatile uint8_t _dyn = (uint8_t)((uintptr_t)(const void *)out);
    for (size_t i = 0; i < ENKO_PERAPK_MAGIC_LEN; i++) {
        uint8_t a = _dyn, b = _dyn;
        out[i] = enc[i] ^ (uint8_t)(salt ^ a) ^ b;
    }
}

int enko_key_deobfuscate(const uint8_t *seed, size_t seed_len,
                          uint8_t *out, size_t out_len) {
    if (seed_len != 16 && seed_len != 32) return -1;
    if (out_len < seed_len) return -1;

    uint8_t mask[ENKO_MAX_KEY_LEN];
    build_mask(mask, 0);  /* no entropy — must match packer-side XOR */

    for (size_t i = 0; i < seed_len; i++) {
        out[i] = seed[i] ^ mask[i];
    }

    enko_secure_wipe(mask, sizeof(mask));
    return 0;
}

int enko_derive_cfg_key(uint8_t out[16]) {
    uint8_t mask[ENKO_MAX_KEY_LEN];
    build_mask(mask, 0);  /* no entropy — must match packer-side derivation */

    uint8_t hash[32];
    enko_sha256(mask, ENKO_MAX_KEY_LEN, hash);
    memcpy(out, hash, 16);

    enko_secure_wipe(mask, sizeof(mask));
    enko_secure_wipe(hash, sizeof(hash));
    return 0;
}

int enko_derive_payload_key(uint8_t out[32]) {
    uint8_t mask[ENKO_MAX_KEY_LEN];
    build_mask(mask, 0);  /* no entropy — must match packer-side derivation */

    char seed_buf[20];
    obs_payload_key_seed_dec(seed_buf, 19);

    enko_sha256_ctx ctx;
    enko_sha256_init(&ctx);
    enko_sha256_update(&ctx, (const uint8_t *)seed_buf, 19);
    enko_sha256_update(&ctx, mask, ENKO_MAX_KEY_LEN);
    enko_sha256_final(&ctx, out);

    enko_secure_wipe(seed_buf, sizeof(seed_buf));

    enko_secure_wipe(mask, sizeof(mask));
    return 0;
}

__attribute__((annotate("fla"), annotate("sub")))
int enko_get_per_apk_payload_key(uint8_t out[32]) {
    if (!out) return -1;

    /* Read per-APK markers from the marker store, or fall back to
     * compile-time constants if the store hasn't been patched. */
    uint8_t head_expected[ENKO_PERAPK_MAGIC_LEN];
    uint8_t tail_expected[ENKO_PERAPK_MAGIC_LEN];

    /* Verify marker store anchor magic. */
    static const uint8_t marker_anchor[ENKO_PERAPK_ANCHOR_LEN] = {
        0xE7,0x3A,0x91,0x5C,0xD2,0x8F,0x46,0xB0
    };
    int store_patched = 1;
    if (memcmp((const void *)ENKO_MARKER_STORE, marker_anchor, ENKO_PERAPK_ANCHOR_LEN) != 0) {
        store_patched = 0;
    }

    /* Check whether head/tail fields in store are non-zero. */
    int head_empty = 1, tail_empty = 1;
    for (size_t i = 0; i < ENKO_PERAPK_MAGIC_LEN; i++) {
        if (ENKO_MARKER_STORE[ENKO_MARKER_STORE_HEAD_OFF + i] != 0) head_empty = 0;
        if (ENKO_MARKER_STORE[ENKO_MARKER_STORE_TAIL_OFF + i] != 0) tail_empty = 0;
    }

    if (store_patched && !head_empty && !tail_empty) {
        /* Use per-APK random markers from the store. */
        for (size_t i = 0; i < ENKO_PERAPK_MAGIC_LEN; i++) {
            head_expected[i] = ENKO_MARKER_STORE[ENKO_MARKER_STORE_HEAD_OFF + i];
            tail_expected[i] = ENKO_MARKER_STORE[ENKO_MARKER_STORE_TAIL_OFF + i];
        }
    } else {
        /* Fall back to compile-time markers (development / unpatched build). */
        decode_perapk_marker(ENKO_PERAPK_HEAD_ENC, HSALT, head_expected);
        decode_perapk_marker(ENKO_PERAPK_TAIL_ENC, TSALT, tail_expected);
    }

    /* Copy the volatile blob to a local buffer for comparison.
     * Use memcmp first to force the linker to keep the blob section —
     * per-byte reads alone are not enough with -fdata-sections --gc-sections. */
    (void)memcmp((const void *)ENKO_PERAPK_KEY_BLOB,
                 (const void *)ENKO_PERAPK_KEY_BLOB + 1, 1);
    uint8_t blob[sizeof(ENKO_PERAPK_KEY_BLOB)];
    for (size_t i = 0; i < sizeof(ENKO_PERAPK_KEY_BLOB); i++) {
        blob[i] = ENKO_PERAPK_KEY_BLOB[i];
    }

    /* Sanity-check magic markers. */
    if (memcmp(blob, head_expected, ENKO_PERAPK_MAGIC_LEN) != 0) {
        enko_secure_wipe(blob, sizeof(blob));
        enko_secure_wipe(head_expected, sizeof(head_expected));
        enko_secure_wipe(tail_expected, sizeof(tail_expected));
        return -1;
    }

    const uint8_t *slot  = blob + ENKO_PERAPK_MAGIC_LEN;
    const uint8_t *check = slot + ENKO_PERAPK_KEY_LEN;
    const uint8_t *tail  = check + ENKO_PERAPK_CHECK_LEN;

    if (memcmp(tail, tail_expected, ENKO_PERAPK_MAGIC_LEN) != 0) {
        enko_secure_wipe(blob, sizeof(blob));
        enko_secure_wipe(head_expected, sizeof(head_expected));
        enko_secure_wipe(tail_expected, sizeof(tail_expected));
        return -1;
    }

    enko_secure_wipe(head_expected, sizeof(head_expected));
    enko_secure_wipe(tail_expected, sizeof(tail_expected));

    /* Detect unpatched slot (all zeros). */
    int slot_all_zero = 1;
    int check_all_zero = 1;
    for (size_t i = 0; i < ENKO_PERAPK_KEY_LEN; i++) {
        if (slot[i] != 0) slot_all_zero = 0;
        if (check[i] != 0) check_all_zero = 0;
    }
    if (slot_all_zero || check_all_zero) {
        enko_secure_wipe(blob, sizeof(blob));
        return -2;
    }

    uint8_t mask[ENKO_MAX_KEY_LEN];
    build_mask(mask, 0);  /* no entropy — must match packer-side XOR */

    for (size_t i = 0; i < ENKO_PERAPK_KEY_LEN; i++) {
        out[i] = slot[i] ^ mask[i];
    }

    /* Verify CHECK == SHA-256(K). */
    uint8_t digest[32];
    enko_sha256(out, ENKO_PERAPK_KEY_LEN, digest);

    uint8_t diff = 0;
    for (size_t i = 0; i < ENKO_PERAPK_CHECK_LEN; i++) {
        diff |= (uint8_t)(digest[i] ^ check[i]);
    }

    enko_secure_wipe(mask, sizeof(mask));
    enko_secure_wipe(digest, sizeof(digest));
    enko_secure_wipe(blob, sizeof(blob));

    if (diff != 0) {
        enko_secure_wipe(out, ENKO_PERAPK_KEY_LEN);
        return -3;
    }

    return 0;
}

void enko_secure_wipe(void *buf, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)buf;
    while (len--) *p++ = 0;
}

int enko_hex_decode(const char *hex, size_t hex_len, uint8_t *out, size_t out_max) {
    if (hex_len % 2 != 0) return -1;
    size_t byte_len = hex_len / 2;
    if (byte_len > out_max) return -1;

    for (size_t i = 0; i < byte_len; i++) {
        int hi, lo;
        char ch = hex[i * 2];
        char cl = hex[i * 2 + 1];

        if (ch >= '0' && ch <= '9') hi = ch - '0';
        else if (ch >= 'A' && ch <= 'F') hi = ch - 'A' + 10;
        else if (ch >= 'a' && ch <= 'f') hi = ch - 'a' + 10;
        else return -1;

        if (cl >= '0' && cl <= '9') lo = cl - '0';
        else if (cl >= 'A' && cl <= 'F') lo = cl - 'A' + 10;
        else if (cl >= 'a' && cl <= 'f') lo = cl - 'a' + 10;
        else return -1;

        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)byte_len;
}
