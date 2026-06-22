#include "enko_extract.h"
#include "enko_gcm.h"
#include "enko_key.h"
#include "enko_obfstr.h"

#include <android/log.h>
#include <pthread.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* "EnkoExtract" (len=11) — obfuscated TAG */
OBFSTR_DECL(obs_ext_tag, 0x82,0xA9,0xAC,0xA8,0x82,0xBF,0xB3,0xB5,0xA6,0xA4,0xB3);
static char g_ext_tag[12];
static void ensure_ext_tag(void) {
    if (g_ext_tag[0] == '\0') obs_ext_tag_dec(g_ext_tag, 11);
}
#define LOGI(...) do { ensure_ext_tag(); __android_log_print(ANDROID_LOG_INFO,  g_ext_tag, __VA_ARGS__); } while(0)
#define LOGW(...) do { ensure_ext_tag(); __android_log_print(ANDROID_LOG_WARN,  g_ext_tag, __VA_ARGS__); } while(0)
#define LOGE(...) do { ensure_ext_tag(); __android_log_print(ANDROID_LOG_ERROR, g_ext_tag, __VA_ARGS__); } while(0)

/* "T9qE1vN6pM3uC7x" (len=15) — obfuscated magic */
OBFSTR_DECL(obs_ext_magic, 0x93,0xFE,0xB6,0x82,0xF6,0xB1,0x89,0xF1,0xB7,0x8A,0xF4,0xB2,0x84,0xF0,0xBF);

/* ── Internal structures ─────────────────────────────────────────────── */

typedef struct {
    uint16_t dex_index;
    uint8_t  restored;           /* 0/1: whether this entry has been restored */
    uint32_t insns_file_offset;  /* byte offset within the DEX file */
    uint32_t insns_byte_len;
    uint8_t *insns_data;         /* owned, must free */
} extract_entry_t;

typedef struct {
    char     *class_desc;      /* owned, e.g. "Lcom/example/Foo;" */
    uint32_t *entry_indices;   /* owned indices into g_ctx.methods */
    uint32_t  count;
    uint32_t  cap;
} extract_class_bucket_t;

typedef struct {
    uint32_t hash;
    uint32_t bucket_idx;       /* UINT32_MAX => empty */
} extract_class_slot_t;

typedef struct {
    /* Loaded extraction entries */
    uint32_t        method_count;
    uint32_t        pending_count;
    extract_entry_t *methods;      /* owned array */
    int             loaded;

    /* Bound DEX buffers (DirectByteBuffer native addresses) */
    int        dex_count;
    uintptr_t *dex_addrs;          /* owned array */
    int32_t   *dex_sizes;          /* owned array */
    int        dex_bound;

    /* Index: class_desc -> [entry_index...] */
    extract_class_bucket_t *buckets;    /* owned array */
    uint32_t bucket_count;
    uint32_t bucket_cap;

    extract_class_slot_t *class_map;    /* owned hash map */
    uint32_t class_map_cap;
    uint32_t class_map_mask;
    int indexed;
} extract_ctx_t;

static extract_ctx_t g_ctx;
static pthread_mutex_t g_ctx_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ── Reader helpers ──────────────────────────────────────────────────── */

typedef struct {
    const uint8_t *buf;
    size_t len;
    size_t off;
} rd_t;

static int rd_u16(rd_t *r, uint16_t *out) {
    if (r->off + 2 > r->len) return -1;
    *out = (uint16_t)(r->buf[r->off] | ((uint16_t)r->buf[r->off + 1] << 8));
    r->off += 2;
    return 0;
}

static int rd_u32(rd_t *r, uint32_t *out) {
    if (r->off + 4 > r->len) return -1;
    *out = (uint32_t)r->buf[r->off]
         | ((uint32_t)r->buf[r->off + 1] << 8)
         | ((uint32_t)r->buf[r->off + 2] << 16)
         | ((uint32_t)r->buf[r->off + 3] << 24);
    r->off += 4;
    return 0;
}

/* ── Internal helpers ────────────────────────────────────────────────── */

static void extract_free_index_locked(void) {
    if (g_ctx.class_map) {
        free(g_ctx.class_map);
    }
    g_ctx.class_map = NULL;
    g_ctx.class_map_cap = 0;
    g_ctx.class_map_mask = 0;

    if (g_ctx.buckets) {
        for (uint32_t i = 0; i < g_ctx.bucket_count; i++) {
            free(g_ctx.buckets[i].class_desc);
            free(g_ctx.buckets[i].entry_indices);
        }
        free(g_ctx.buckets);
    }
    g_ctx.buckets = NULL;
    g_ctx.bucket_count = 0;
    g_ctx.bucket_cap = 0;
    g_ctx.indexed = 0;
}

static void extract_free_dex_buffers_locked(void) {
    free(g_ctx.dex_addrs);
    free(g_ctx.dex_sizes);
    g_ctx.dex_addrs = NULL;
    g_ctx.dex_sizes = NULL;
    g_ctx.dex_count = 0;
    g_ctx.dex_bound = 0;
}

static void extract_free_methods_locked(void) {
    if (g_ctx.methods) {
        for (uint32_t i = 0; i < g_ctx.method_count; i++) {
            if (g_ctx.methods[i].insns_data) {
                enko_secure_wipe(g_ctx.methods[i].insns_data, g_ctx.methods[i].insns_byte_len);
                free(g_ctx.methods[i].insns_data);
            }
        }
        free(g_ctx.methods);
    }
    g_ctx.methods = NULL;
    g_ctx.method_count = 0;
    g_ctx.pending_count = 0;
    g_ctx.loaded = 0;
}

static void extract_ctx_reset_locked(void) {
    extract_free_index_locked();
    extract_free_dex_buffers_locked();
    extract_free_methods_locked();
}

static uint32_t hash_fnv1a(const char *s) {
    uint32_t h = 2166136261u;
    if (!s) return h;
    while (*s) {
        h ^= (uint8_t)*s++;
        h *= 16777619u;
    }
    return h ? h : 1u;
}

static uint32_t next_pow2_u32(uint32_t v) {
    if (v < 2) return 2;
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v++;
    return v;
}

static int bucket_ensure_cap(extract_class_bucket_t *b, uint32_t need) {
    if (!b) return -1;
    if (need <= b->cap) return 0;

    uint32_t new_cap = b->cap ? b->cap : 4;
    while (new_cap < need) {
        if (new_cap > (UINT32_MAX / 2)) return -1;
        new_cap *= 2;
    }

    uint32_t *p = (uint32_t *)realloc(b->entry_indices, sizeof(uint32_t) * new_cap);
    if (!p) return -1;
    b->entry_indices = p;
    b->cap = new_cap;
    return 0;
}

static int bucket_append(uint32_t bucket_idx, uint32_t entry_idx) {
    if (bucket_idx >= g_ctx.bucket_count) return -1;
    extract_class_bucket_t *b = &g_ctx.buckets[bucket_idx];
    if (bucket_ensure_cap(b, b->count + 1) != 0) return -1;
    b->entry_indices[b->count++] = entry_idx;
    return 0;
}

static int buckets_find(const char *class_desc) {
    if (!class_desc) return -1;
    for (uint32_t i = 0; i < g_ctx.bucket_count; i++) {
        const char *k = g_ctx.buckets[i].class_desc;
        if (k && strcmp(k, class_desc) == 0) return (int)i;
    }
    return -1;
}

static int buckets_create_take(char *class_desc, uint32_t *out_idx) {
    if (!class_desc || !out_idx) return -1;

    if (g_ctx.bucket_count == g_ctx.bucket_cap) {
        uint32_t new_cap = g_ctx.bucket_cap ? (g_ctx.bucket_cap * 2) : 16;
        extract_class_bucket_t *p = (extract_class_bucket_t *)realloc(
            g_ctx.buckets, sizeof(extract_class_bucket_t) * new_cap);
        if (!p) return -1;
        g_ctx.buckets = p;
        g_ctx.bucket_cap = new_cap;
    }

    uint32_t idx = g_ctx.bucket_count++;
    extract_class_bucket_t *b = &g_ctx.buckets[idx];
    memset(b, 0, sizeof(*b));
    b->class_desc = class_desc; /* take ownership */

    *out_idx = idx;
    return 0;
}

static int class_map_build_locked(void) {
    if (g_ctx.class_map) {
        free(g_ctx.class_map);
        g_ctx.class_map = NULL;
    }
    g_ctx.class_map_cap = 0;
    g_ctx.class_map_mask = 0;

    if (g_ctx.bucket_count == 0) {
        return 0;
    }

    uint32_t wanted = g_ctx.bucket_count * 2;
    if (wanted < g_ctx.bucket_count) return -1; /* overflow */
    uint32_t cap = next_pow2_u32(wanted);

    extract_class_slot_t *slots = (extract_class_slot_t *)calloc(cap, sizeof(extract_class_slot_t));
    if (!slots) return -1;
    for (uint32_t i = 0; i < cap; i++) {
        slots[i].bucket_idx = UINT32_MAX;
    }

    uint32_t mask = cap - 1;
    for (uint32_t bi = 0; bi < g_ctx.bucket_count; bi++) {
        const char *k = g_ctx.buckets[bi].class_desc;
        if (!k) continue;
        uint32_t h = hash_fnv1a(k);
        uint32_t idx = h & mask;
        while (slots[idx].bucket_idx != UINT32_MAX) {
            idx = (idx + 1) & mask;
        }
        slots[idx].hash = h;
        slots[idx].bucket_idx = bi;
    }

    g_ctx.class_map = slots;
    g_ctx.class_map_cap = cap;
    g_ctx.class_map_mask = mask;
    return 0;
}

static int class_map_lookup_locked(const char *class_desc, uint32_t *out_bucket_idx) {
    if (!class_desc || !out_bucket_idx) return -1;
    if (!g_ctx.class_map || g_ctx.class_map_cap == 0) return 1;

    uint32_t h = hash_fnv1a(class_desc);
    uint32_t idx = h & g_ctx.class_map_mask;
    for (uint32_t n = 0; n < g_ctx.class_map_cap; n++) {
        extract_class_slot_t *s = &g_ctx.class_map[idx];
        if (s->bucket_idx == UINT32_MAX) return 1; /* not found */
        if (s->hash == h) {
            uint32_t bi = s->bucket_idx;
            if (bi < g_ctx.bucket_count) {
                const char *k = g_ctx.buckets[bi].class_desc;
                if (k && strcmp(k, class_desc) == 0) {
                    *out_bucket_idx = bi;
                    return 0;
                }
            }
        }
        idx = (idx + 1) & g_ctx.class_map_mask;
    }
    return 1;
}

static int read_uleb128(const uint8_t *buf, size_t len, size_t *off_io, uint32_t *out) {
    if (!buf || !off_io || !out) return -1;

    uint32_t result = 0;
    int shift = 0;
    size_t off = *off_io;
    for (;;) {
        if (off >= len) return -1;
        uint8_t b = buf[off++];
        result |= ((uint32_t)(b & 0x7F)) << shift;
        if ((b & 0x80) == 0) break;
        shift += 7;
        if (shift > 28) return -1;
    }

    *off_io = off;
    *out = result;
    return 0;
}

static int dex_read_u32(const uint8_t *dex, size_t dex_len, size_t off, uint32_t *out) {
    if (!dex || !out) return -1;
    if (off + 4 > dex_len) return -1;
    const uint8_t *p = dex + off;
    *out = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    return 0;
}

static char *dex_dup_string(
    const uint8_t *dex,
    size_t dex_len,
    uint32_t string_ids_off,
    uint32_t string_ids_size,
    uint32_t string_idx
) {
    if (!dex) return NULL;
    if (string_idx >= string_ids_size) return NULL;

    uint32_t str_data_off = 0;
    if (dex_read_u32(dex, dex_len, (size_t)string_ids_off + (size_t)string_idx * 4u, &str_data_off) != 0) {
        return NULL;
    }
    if (str_data_off >= dex_len) return NULL;

    size_t pos = (size_t)str_data_off;
    uint32_t ignored_len = 0;
    if (read_uleb128(dex, dex_len, &pos, &ignored_len) != 0) {
        return NULL;
    }

    size_t start = pos;
    while (pos < dex_len && dex[pos] != 0) {
        pos++;
    }
    if (pos >= dex_len) return NULL;

    size_t n = pos - start;
    char *out = (char *)malloc(n + 1);
    if (!out) return NULL;
    memcpy(out, dex + start, n);
    out[n] = '\0';
    return out;
}

static char *dex_dup_type_desc(
    const uint8_t *dex,
    size_t dex_len,
    uint32_t string_ids_off,
    uint32_t string_ids_size,
    uint32_t type_ids_off,
    uint32_t type_ids_size,
    uint32_t type_idx
) {
    if (!dex) return NULL;
    if (type_idx >= type_ids_size) return NULL;

    uint32_t string_idx = 0;
    if (dex_read_u32(dex, dex_len, (size_t)type_ids_off + (size_t)type_idx * 4u, &string_idx) != 0) {
        return NULL;
    }
    return dex_dup_string(dex, dex_len, string_ids_off, string_ids_size, string_idx);
}

typedef struct {
    uint32_t key;
    int32_t value; /* entry index */
} off_slot_t;

typedef struct {
    off_slot_t *slots;
    uint32_t cap;
    uint32_t mask;
} off_map_t;

static void off_map_free(off_map_t *m) {
    if (!m) return;
    free(m->slots);
    m->slots = NULL;
    m->cap = 0;
    m->mask = 0;
}

static uint32_t off_hash_u32(uint32_t x) {
    return x * 2654435761u;
}

static int off_map_init(off_map_t *m, uint32_t expected) {
    if (!m) return -1;
    memset(m, 0, sizeof(*m));
    if (expected == 0) {
        return 0;
    }

    uint32_t wanted = expected * 2;
    if (wanted < expected) return -1;
    uint32_t cap = next_pow2_u32(wanted);

    off_slot_t *slots = (off_slot_t *)calloc(cap, sizeof(off_slot_t));
    if (!slots) return -1;
    for (uint32_t i = 0; i < cap; i++) {
        slots[i].value = -1;
    }

    m->slots = slots;
    m->cap = cap;
    m->mask = cap - 1;
    return 0;
}

static int off_map_put(off_map_t *m, uint32_t key, int32_t value) {
    if (!m || !m->slots || m->cap == 0) return -1;

    uint32_t idx = off_hash_u32(key) & m->mask;
    for (uint32_t n = 0; n < m->cap; n++) {
        if (m->slots[idx].value == -1) {
            m->slots[idx].key = key;
            m->slots[idx].value = value;
            return 0;
        }
        if (m->slots[idx].key == key) {
            /* Duplicate offset: keep the first entry. */
            return 0;
        }
        idx = (idx + 1) & m->mask;
    }
    return -1;
}

static int off_map_get(off_map_t *m, uint32_t key, int32_t *out_value) {
    if (!m || !out_value) return -1;
    if (!m->slots || m->cap == 0) return 1;

    uint32_t idx = off_hash_u32(key) & m->mask;
    for (uint32_t n = 0; n < m->cap; n++) {
        int32_t v = m->slots[idx].value;
        if (v == -1) return 1;
        if (m->slots[idx].key == key) {
            *out_value = v;
            return 0;
        }
        idx = (idx + 1) & m->mask;
    }
    return 1;
}

static int extract_build_index_locked(void) {
    if (!g_ctx.loaded || !g_ctx.dex_bound || !g_ctx.methods) {
        return -1;
    }

    /* Clear any previous index (but keep methods + dex buffers). */
    extract_free_index_locked();

    /* Validate extraction entries' dex_index. */
    for (uint32_t i = 0; i < g_ctx.method_count; i++) {
        int idx = (int)g_ctx.methods[i].dex_index;
        if (idx < 0 || idx >= g_ctx.dex_count) {
            LOGE("extract index: entry %u has dex_index %d out of range (dex_count=%d)",
                 i, idx, g_ctx.dex_count);
            return -1;
        }
    }

    uint8_t *matched = (uint8_t *)calloc(g_ctx.method_count, 1);
    if (!matched) return -1;

    for (int dex_idx = 0; dex_idx < g_ctx.dex_count; dex_idx++) {
        uintptr_t base = g_ctx.dex_addrs[dex_idx];
        int32_t size = g_ctx.dex_sizes[dex_idx];
        if (base == 0 || size <= 0) {
            LOGE("extract index: invalid dex buffer %d (base=%p size=%d)", dex_idx, (void *)base, (int)size);
            free(matched);
            return -1;
        }

        const uint8_t *dex = (const uint8_t *)base;
        size_t dex_len = (size_t)size;

        uint32_t endian_tag = 0;
        if (dex_read_u32(dex, dex_len, 40, &endian_tag) != 0 || endian_tag != 0x12345678u) {
            LOGE("extract index: bad dex endian tag for dex %d", dex_idx);
            free(matched);
            return -1;
        }

        uint32_t string_ids_size = 0, string_ids_off = 0;
        uint32_t type_ids_size = 0, type_ids_off = 0;
        uint32_t class_defs_size = 0, class_defs_off = 0;
        if (dex_read_u32(dex, dex_len, 56, &string_ids_size) != 0 ||
            dex_read_u32(dex, dex_len, 60, &string_ids_off) != 0 ||
            dex_read_u32(dex, dex_len, 64, &type_ids_size) != 0 ||
            dex_read_u32(dex, dex_len, 68, &type_ids_off) != 0 ||
            dex_read_u32(dex, dex_len, 96, &class_defs_size) != 0 ||
            dex_read_u32(dex, dex_len, 100, &class_defs_off) != 0) {
            LOGE("extract index: truncated dex header for dex %d", dex_idx);
            free(matched);
            return -1;
        }

        if ((uint64_t)class_defs_off + (uint64_t)class_defs_size * 32u > (uint64_t)dex_len) {
            LOGE("extract index: class_defs out of range for dex %d", dex_idx);
            free(matched);
            return -1;
        }

        /* Build insns_off -> extraction entry index map for this dex. */
        uint32_t expected = 0;
        for (uint32_t i = 0; i < g_ctx.method_count; i++) {
            if (g_ctx.methods[i].restored) continue;
            if ((int)g_ctx.methods[i].dex_index == dex_idx) expected++;
        }

        off_map_t om;
        if (off_map_init(&om, expected) != 0) {
            free(matched);
            return -1;
        }
        for (uint32_t i = 0; i < g_ctx.method_count; i++) {
            extract_entry_t *e = &g_ctx.methods[i];
            if (e->restored) continue;
            if ((int)e->dex_index != dex_idx) continue;
            if (off_map_put(&om, e->insns_file_offset, (int32_t)i) != 0) {
                off_map_free(&om);
                free(matched);
                return -1;
            }
        }

        /* Walk all classes, match code_item.insns_off to extraction entries. */
        for (uint32_t ci = 0; ci < class_defs_size; ci++) {
            size_t cbase = (size_t)class_defs_off + (size_t)ci * 32u;
            uint32_t class_idx = 0;
            uint32_t class_data_off = 0;
            if (dex_read_u32(dex, dex_len, cbase, &class_idx) != 0 ||
                dex_read_u32(dex, dex_len, cbase + 24u, &class_data_off) != 0) {
                off_map_free(&om);
                free(matched);
                return -1;
            }
            if (class_data_off == 0) continue;
            if (class_data_off >= dex_len) {
                off_map_free(&om);
                free(matched);
                return -1;
            }

            char *class_desc = dex_dup_type_desc(
                dex, dex_len,
                string_ids_off, string_ids_size,
                type_ids_off, type_ids_size,
                class_idx);
            if (!class_desc) {
                off_map_free(&om);
                free(matched);
                return -1;
            }

            int existing = buckets_find(class_desc);
            uint32_t bucket_idx = 0;
            if (existing >= 0) {
                bucket_idx = (uint32_t)existing;
                free(class_desc);
                class_desc = NULL;
            } else {
                if (buckets_create_take(class_desc, &bucket_idx) != 0) {
                    free(class_desc);
                    off_map_free(&om);
                    free(matched);
                    return -1;
                }
                class_desc = NULL; /* taken */
            }

            size_t pos = (size_t)class_data_off;
            uint32_t sf_size = 0, if_size = 0, dm_size = 0, vm_size = 0;
            if (read_uleb128(dex, dex_len, &pos, &sf_size) != 0 ||
                read_uleb128(dex, dex_len, &pos, &if_size) != 0 ||
                read_uleb128(dex, dex_len, &pos, &dm_size) != 0 ||
                read_uleb128(dex, dex_len, &pos, &vm_size) != 0) {
                off_map_free(&om);
                free(matched);
                return -1;
            }

            /* Skip static + instance fields. */
            for (uint32_t i = 0; i < sf_size; i++) {
                uint32_t tmp;
                if (read_uleb128(dex, dex_len, &pos, &tmp) != 0 ||
                    read_uleb128(dex, dex_len, &pos, &tmp) != 0) {
                    off_map_free(&om);
                    free(matched);
                    return -1;
                }
            }
            for (uint32_t i = 0; i < if_size; i++) {
                uint32_t tmp;
                if (read_uleb128(dex, dex_len, &pos, &tmp) != 0 ||
                    read_uleb128(dex, dex_len, &pos, &tmp) != 0) {
                    off_map_free(&om);
                    free(matched);
                    return -1;
                }
            }

            /* Direct + virtual methods. */
            uint32_t mcount = dm_size + vm_size;
            for (uint32_t mi = 0; mi < mcount; mi++) {
                uint32_t tmp;
                uint32_t code_off = 0;
                if (read_uleb128(dex, dex_len, &pos, &tmp) != 0 ||  /* method_idx_diff */
                    read_uleb128(dex, dex_len, &pos, &tmp) != 0 ||  /* access_flags */
                    read_uleb128(dex, dex_len, &pos, &code_off) != 0) {
                    off_map_free(&om);
                    free(matched);
                    return -1;
                }
                if (code_off == 0) continue;
                if (code_off > UINT32_MAX - 16u) continue;

                uint32_t insns_off = code_off + 16u;
                int32_t entry_idx = -1;
                if (off_map_get(&om, insns_off, &entry_idx) == 0 && entry_idx >= 0) {
                    if ((uint32_t)entry_idx < g_ctx.method_count) {
                        if (bucket_append(bucket_idx, (uint32_t)entry_idx) != 0) {
                            off_map_free(&om);
                            free(matched);
                            return -1;
                        }
                        matched[entry_idx] = 1;
                    }
                }
            }
        }

        off_map_free(&om);
    }

    /* Ensure every extraction entry is indexable (fail-close). */
    for (uint32_t i = 0; i < g_ctx.method_count; i++) {
        if (g_ctx.methods[i].restored) continue;
        if (!matched[i]) {
            LOGE("extract index: entry %u not found in dex metadata (off=%u dex=%u)",
                 i, g_ctx.methods[i].insns_file_offset, g_ctx.methods[i].dex_index);
            free(matched);
            return -1;
        }
    }
    free(matched);

    if (class_map_build_locked() != 0) {
        return -1;
    }

    g_ctx.indexed = 1;
    LOGI("extract index built: %u class(es)", g_ctx.bucket_count);
    return 0;
}

static int extract_maybe_build_index_locked(void) {
    if (g_ctx.indexed) return 0;
    if (!g_ctx.loaded || !g_ctx.dex_bound) return 0;
    return extract_build_index_locked();
}

/* ── Public API ──────────────────────────────────────────────────────── */

int enko_extract_load(const uint8_t *blob, size_t blob_len) {
    if (!blob || blob_len == 0) return -1;

    pthread_mutex_lock(&g_ctx_mutex);

    /* Clear previous extraction entries + index (keep bound dex buffers if any). */
    extract_free_index_locked();
    extract_free_methods_locked();

    int out_rc = -1;
    uint8_t key[32];
    memset(key, 0, sizeof(key));

    /* Derive payload key (try per-APK first, then legacy). */
    int krc = enko_get_per_apk_payload_key(key);
    if (krc != 0) {
        enko_derive_payload_key(key);
    }

    /* Decrypt blob (reuse the extraction magic). */
    char magic[16];
    memset(magic, 0, sizeof(magic));
    obs_ext_magic_dec(magic, 15);

    /* The blob format is: MAGIC(15) + nonce(12) + ciphertext + tag(16). */
    size_t min_len = 15 + 12 + 16;
    if (blob_len < min_len) {
        LOGE("extract blob too small (%zu)", blob_len);
        goto out;
    }

    if (memcmp(blob, magic, 15) != 0) {
        LOGE("extract blob magic mismatch");
        goto out;
    }
    memset(magic, 0, sizeof(magic));

    /* Rewrite the magic prefix so we can reuse enko_gcm_decrypt(). */
    size_t payload_blob_len = blob_len;
    uint8_t *payload_blob = (uint8_t *)malloc(payload_blob_len);
    if (!payload_blob) {
        goto out;
    }
    memcpy(payload_blob, blob, payload_blob_len);

    {
        /* "Q7mP2t9Lx1cV8rK" len=15, same obfuscated bytes as enko_gcm.c */
        static const uint8_t obs_pm[] = {0x96,0xF0,0xAA,0x97,0xF5,0xB3,0xFE,0x8B,0xBF,0xF6,0xA4,0x91,0xFF,0xB5,0x8C};
        char pm[16];
        for (int i = 0; i < 15; i++) pm[i] = (char)(obs_pm[i] ^ 0xC7);
        pm[15] = '\0';
        memcpy(payload_blob, pm, 15);
        memset(pm, 0, sizeof(pm));
    }

    size_t plain_len = 0;
    uint8_t *plain = enko_gcm_decrypt(key, sizeof(key), payload_blob, payload_blob_len, &plain_len);

    enko_secure_wipe(key, sizeof(key));
    enko_secure_wipe(payload_blob, payload_blob_len);
    free(payload_blob);
    payload_blob = NULL;

    if (!plain) {
        LOGE("extract blob decryption failed");
        goto out;
    }

    /* ---- Parse plaintext ---- */
    rd_t rd = { .buf = plain, .len = plain_len, .off = 0 };

    uint32_t method_count = 0;
    if (rd_u32(&rd, &method_count) != 0 || method_count == 0) {
        LOGE("extract blob: bad method count");
        enko_secure_wipe(plain, plain_len);
        free(plain);
        plain = NULL;
        goto out;
    }

    extract_entry_t *methods = (extract_entry_t *)calloc(method_count, sizeof(extract_entry_t));
    if (!methods) {
        enko_secure_wipe(plain, plain_len);
        free(plain);
        plain = NULL;
        goto out;
    }

    for (uint32_t i = 0; i < method_count; i++) {
        uint16_t dex_idx = 0;
        uint32_t off = 0, blen = 0;
        if (rd_u16(&rd, &dex_idx) != 0 ||
            rd_u32(&rd, &off) != 0 ||
            rd_u32(&rd, &blen) != 0) {
            LOGE("extract blob: truncated entry %u", i);
            goto parse_error;
        }
        if (rd.off + blen > rd.len) {
            LOGE("extract blob: insns data overflow at entry %u", i);
            goto parse_error;
        }

        methods[i].dex_index = dex_idx;
        methods[i].restored = 0;
        methods[i].insns_file_offset = off;
        methods[i].insns_byte_len = blen;

        methods[i].insns_data = (uint8_t *)malloc(blen);
        if (!methods[i].insns_data) goto parse_error;
        memcpy(methods[i].insns_data, rd.buf + rd.off, blen);
        rd.off += blen;
    }

    /* Wipe plaintext immediately. */
    enko_secure_wipe(plain, plain_len);
    free(plain);
    plain = NULL;

    g_ctx.method_count = method_count;
    g_ctx.pending_count = method_count;
    g_ctx.methods = methods;
    g_ctx.loaded = 1;

    if (extract_maybe_build_index_locked() != 0) {
        LOGE("extract: index build failed");
        extract_free_index_locked();
        extract_free_methods_locked();
        goto out;
    }

    LOGI("extract: loaded %u method(s)", method_count);
    out_rc = 0;
    goto out;

parse_error:
    for (uint32_t j = 0; j < method_count; j++) {
        if (methods[j].insns_data) {
            enko_secure_wipe(methods[j].insns_data, methods[j].insns_byte_len);
            free(methods[j].insns_data);
        }
    }
    free(methods);
    enko_secure_wipe(plain, plain_len);
    free(plain);
    plain = NULL;

out:
    /* Ensure key material is not kept on stack longer than necessary. */
    enko_secure_wipe(key, sizeof(key));
    pthread_mutex_unlock(&g_ctx_mutex);
    return out_rc;
}


/* ── bind_dex_buffers ────────────────────────────────────────────────── */

int enko_extract_bind_dex_buffers(const uintptr_t *dex_addrs,
                                  const int32_t   *dex_sizes,
                                  int              dex_count) {
    if (!dex_addrs || !dex_sizes || dex_count <= 0) return -1;

    pthread_mutex_lock(&g_ctx_mutex);
    int rc = -1;

    /* Free previous dex buffer refs + index (index depends on dex buffers). */
    extract_free_index_locked();
    extract_free_dex_buffers_locked();

    g_ctx.dex_addrs = (uintptr_t *)malloc(sizeof(uintptr_t) * (size_t)dex_count);
    g_ctx.dex_sizes = (int32_t   *)malloc(sizeof(int32_t)   * (size_t)dex_count);
    if (!g_ctx.dex_addrs || !g_ctx.dex_sizes) {
        extract_free_dex_buffers_locked();
        goto out;
    }
    memcpy(g_ctx.dex_addrs, dex_addrs, sizeof(uintptr_t) * (size_t)dex_count);
    memcpy(g_ctx.dex_sizes, dex_sizes, sizeof(int32_t)   * (size_t)dex_count);
    g_ctx.dex_count = dex_count;
    g_ctx.dex_bound = 1;

    /* If extraction entries are already loaded, build index eagerly. */
    if (extract_maybe_build_index_locked() != 0) {
        LOGE("extract: bind_dex_buffers index build failed");
        extract_free_index_locked();
        extract_free_dex_buffers_locked();
        goto out;
    }

    LOGI("extract: bound %d dex buffer(s)", dex_count);
    rc = 0;

out:
    pthread_mutex_unlock(&g_ctx_mutex);
    return rc;
}

/* ── restore_class (on-demand, per-class) ────────────────────────────── */

int enko_extract_restore_class(const char *class_desc) {
    if (!class_desc) return -1;

    pthread_mutex_lock(&g_ctx_mutex);

    if (!g_ctx.dex_bound) {
        pthread_mutex_unlock(&g_ctx_mutex);
        return -1;  /* fail-close: not ready */
    }
    if (!g_ctx.loaded) {
        pthread_mutex_unlock(&g_ctx_mutex);
        return 0;   /* nothing to do (already fully restored / not active) */
    }
    if (!g_ctx.indexed) {
        pthread_mutex_unlock(&g_ctx_mutex);
        return -1;  /* fail-close: loaded but index missing */
    }

    uint32_t bucket_idx = 0;
    int lrc = class_map_lookup_locked(class_desc, &bucket_idx);
    if (lrc != 0) {
        /* class not in extraction set — nothing to restore, not an error */
        pthread_mutex_unlock(&g_ctx_mutex);
        return 0;
    }

    extract_class_bucket_t *b = &g_ctx.buckets[bucket_idx];
    int restored = 0;

    for (uint32_t i = 0; i < b->count; i++) {
        uint32_t eidx = b->entry_indices[i];
        if (eidx >= g_ctx.method_count) continue;
        extract_entry_t *e = &g_ctx.methods[eidx];

        if (e->restored) continue;
        if (!e->insns_data) {
            LOGE("extract restore_class: entry %u has NULL insns_data", eidx);
            pthread_mutex_unlock(&g_ctx_mutex);
            return -1;  /* fail-close */
        }

        int didx = (int)e->dex_index;
        if (didx < 0 || didx >= g_ctx.dex_count) {
            LOGE("extract restore_class: dex_index %d out of range", didx);
            pthread_mutex_unlock(&g_ctx_mutex);
            return -1;
        }

        uintptr_t base = g_ctx.dex_addrs[didx];
        int32_t   dsize = g_ctx.dex_sizes[didx];
        uint32_t  off = e->insns_file_offset;
        uint32_t  blen = e->insns_byte_len;

        if (base == 0 || dsize <= 0 || off + blen > (uint32_t)dsize) {
            LOGE("extract restore_class: bounds check failed entry %u", eidx);
            pthread_mutex_unlock(&g_ctx_mutex);
            return -1;
        }

        /* Write original insns back into in-memory DEX. */
        memcpy((void *)(base + off), e->insns_data, blen);

        /* Wipe and release insns_data immediately. */
        enko_secure_wipe(e->insns_data, blen);
        free(e->insns_data);
        e->insns_data = NULL;
        e->restored = 1;

        if (g_ctx.pending_count > 0) {
            g_ctx.pending_count--;
        }
        restored++;
    }

    /* If all entries have been restored, tear down extraction state. */
    if (g_ctx.pending_count == 0) {
        LOGI("extract: all methods restored, freeing extraction state");
        extract_free_index_locked();
        extract_free_methods_locked();
        /* Keep dex_bound — it's just pointers, harmless. */
    }

    pthread_mutex_unlock(&g_ctx_mutex);
    return restored;
}

/* ── Legacy bulk restore ─────────────────────────────────────────────── */

int enko_extract_restore(const uintptr_t *dex_addrs, const int32_t *dex_sizes,
                         int dex_count) {
    if (!dex_addrs || !dex_sizes || dex_count <= 0) return -1;

    pthread_mutex_lock(&g_ctx_mutex);

    if (!g_ctx.loaded) {
        pthread_mutex_unlock(&g_ctx_mutex);
        return -1;
    }

    int restored = 0;

    for (uint32_t i = 0; i < g_ctx.method_count; i++) {
        extract_entry_t *e = &g_ctx.methods[i];
        if (e->restored || !e->insns_data) continue;

        int idx = (int)e->dex_index;
        if (idx < 0 || idx >= dex_count) {
            LOGW("extract: dex_index %d out of range (count=%d)", idx, dex_count);
            continue;
        }

        uintptr_t base = dex_addrs[idx];
        int32_t   size = dex_sizes[idx];
        if (base == 0 || size <= 0) continue;

        uint32_t off = e->insns_file_offset;
        uint32_t len = e->insns_byte_len;

        if (off + len > (uint32_t)size) {
            LOGW("extract: offset %u + len %u exceeds dex size %d", off, len, size);
            continue;
        }

        memcpy((void *)(base + off), e->insns_data, len);
        restored++;
    }

    LOGI("extract: restored %d/%u method(s) (legacy)", restored, g_ctx.method_count);

    /* Wipe all extraction data. */
    extract_free_index_locked();
    extract_free_methods_locked();

    pthread_mutex_unlock(&g_ctx_mutex);
    return restored;
}

/* ── free ─────────────────────────────────────────────────────────────── */

void enko_extract_free(void) {
    pthread_mutex_lock(&g_ctx_mutex);
    extract_ctx_reset_locked();
    pthread_mutex_unlock(&g_ctx_mutex);
}
