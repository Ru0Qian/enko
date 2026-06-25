#include "enko_vmp.h"
#include "enko_obfstr.h"

#include <android/log.h>

#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

/* ── NEON SIMD acceleration for bulk register operations ──────────────
 * ARM NEON stores 16 bytes per vst1q; vmp_reg_t = 8 bytes, so we can
 * zero 2 registers per NEON store (128-bit).  For VMP_MAX_REGS=256
 * that is 256 * 8 = 2048 bytes → 128 NEON stores vs 256 memset bytes.
 * GCC/Clang on ARM will vectorize memset, but explicit NEON guarantees
 * 128-bit aligned stores and avoids call overhead on older NDK.
 */
#if defined(__ARM_NEON) || defined(__ARM_NEON__)
#include <arm_neon.h>
static inline void vmp_zero_regs(vmp_reg_t *regs, int count) {
    uint8_t *p = (uint8_t *)regs;
    size_t bytes = (size_t)count * sizeof(vmp_reg_t);
    size_t i = 0;
    uint8x16_t zero = vdupq_n_u8(0);
    for (; i + 16 <= bytes; i += 16) {
        vst1q_u8(p + i, zero);
    }
    for (; i < bytes; i++) {
        p[i] = 0;
    }
}
#else
static inline void vmp_zero_regs(vmp_reg_t *regs, int count) {
    memset(regs, 0, (size_t)count * sizeof(vmp_reg_t));
}
#endif

/* "EnkoVMP" (len=7) — obfuscated TAG */
OBFSTR_DECL(obs_vmp_tag, 0x82,0xA9,0xAC,0xA8,0x91,0x8A,0x97);
static char g_vmp_tag[8];
static void ensure_vmp_tag(void) {
    if (g_vmp_tag[0] == '\0') obs_vmp_tag_dec(g_vmp_tag, 7);
}
#define LOGI(...) do { ensure_vmp_tag(); __android_log_print(ANDROID_LOG_INFO,  g_vmp_tag, __VA_ARGS__); } while(0)
#define LOGW(...) do { ensure_vmp_tag(); __android_log_print(ANDROID_LOG_WARN,  g_vmp_tag, __VA_ARGS__); } while(0)
#define LOGE(...) do { ensure_vmp_tag(); __android_log_print(ANDROID_LOG_ERROR, g_vmp_tag, __VA_ARGS__); } while(0)

/* ── Obfuscated JNI class/method strings ──────────────────────────────── */
OBFSTR_DECL(obs_libstub, 0xAB,0xAE,0xA5,0xA6,0xA0,0xB7,0xB4,0xB3,0xB2,0xA5,0xE9,0xB4,0xA8);
OBFSTR_DECL(obs_stub_init, 0xA2,0xA9,0xAC,0xA8,0x98,0xB1,0xAA,0xB7,0x98,0xB4,0xB3,0xB2,0xA5,0x98,0xAE,0xA9,0xAE,0xB3);
OBFSTR_DECL(obs_j_integer, 0xAD,0xA6,0xB1,0xA6,0xE8,0xAB,0xA6,0xA9,0xA0,0xE8,0x8E,0xA9,0xB3,0xA2,0xA0,0xA2,0xB5);
OBFSTR_DECL(obs_j_long, 0xAD,0xA6,0xB1,0xA6,0xE8,0xAB,0xA6,0xA9,0xA0,0xE8,0x8B,0xA8,0xA9,0xA0);
OBFSTR_DECL(obs_j_float, 0xAD,0xA6,0xB1,0xA6,0xE8,0xAB,0xA6,0xA9,0xA0,0xE8,0x81,0xAB,0xA8,0xA6,0xB3);
OBFSTR_DECL(obs_j_double, 0xAD,0xA6,0xB1,0xA6,0xE8,0xAB,0xA6,0xA9,0xA0,0xE8,0x83,0xA8,0xB2,0xA5,0xAB,0xA2);
OBFSTR_DECL(obs_j_boolean, 0xAD,0xA6,0xB1,0xA6,0xE8,0xAB,0xA6,0xA9,0xA0,0xE8,0x85,0xA8,0xA8,0xAB,0xA2,0xA6,0xA9);
OBFSTR_DECL(obs_j_byte, 0xAD,0xA6,0xB1,0xA6,0xE8,0xAB,0xA6,0xA9,0xA0,0xE8,0x85,0xBE,0xB3,0xA2);
OBFSTR_DECL(obs_j_short, 0xAD,0xA6,0xB1,0xA6,0xE8,0xAB,0xA6,0xA9,0xA0,0xE8,0x94,0xAF,0xA8,0xB5,0xB3);
OBFSTR_DECL(obs_j_char, 0xAD,0xA6,0xB1,0xA6,0xE8,0xAB,0xA6,0xA9,0xA0,0xE8,0x84,0xAF,0xA6,0xB5,0xA6,0xA4,0xB3,0xA2,0xB5);
OBFSTR_DECL(obs_j_void, 0xAD,0xA6,0xB1,0xA6,0xE8,0xAB,0xA6,0xA9,0xA0,0xE8,0x91,0xA8,0xAE,0xA3);
OBFSTR_DECL(obs_j_number, 0xAD,0xA6,0xB1,0xA6,0xE8,0xAB,0xA6,0xA9,0xA0,0xE8,0x89,0xB2,0xAA,0xA5,0xA2,0xB5);
OBFSTR_DECL(obs_j_classloader, 0xAD,0xA6,0xB1,0xA6,0xE8,0xAB,0xA6,0xA9,0xA0,0xE8,0x84,0xAB,0xA6,0xB4,0xB4,0x8B,0xA8,0xA6,0xA3,0xA2,0xB5);
OBFSTR_DECL(obs_j_rte, 0xAD,0xA6,0xB1,0xA6,0xE8,0xAB,0xA6,0xA9,0xA0,0xE8,0x95,0xB2,0xA9,0xB3,0xAE,0xAA,0xA2,0x82,0xBF,0xA4,0xA2,0xB7,0xB3,0xAE,0xA8,0xA9);
OBFSTR_DECL(obs_j_arith, 0xAD,0xA6,0xB1,0xA6,0xE8,0xAB,0xA6,0xA9,0xA0,0xE8,0x86,0xB5,0xAE,0xB3,0xAF,0xAA,0xA2,0xB3,0xAE,0xA4,0x82,0xBF,0xA4,0xA2,0xB7,0xB3,0xAE,0xA8,0xA9);
OBFSTR_DECL(obs_j_npe, 0xAD,0xA6,0xB1,0xA6,0xE8,0xAB,0xA6,0xA9,0xA0,0xE8,0x89,0xB2,0xAB,0xAB,0x97,0xA8,0xAE,0xA9,0xB3,0xA2,0xB5,0x82,0xBF,0xA4,0xA2,0xB7,0xB3,0xAE,0xA8,0xA9);
OBFSTR_DECL(obs_j_class, 0xAD,0xA6,0xB1,0xA6,0xE8,0xAB,0xA6,0xA9,0xA0,0xE8,0x84,0xAB,0xA6,0xB4,0xB4);
OBFSTR_DECL(obs_j_object, 0xAD,0xA6,0xB1,0xA6,0xE8,0xAB,0xA6,0xA9,0xA0,0xE8,0x88,0xA5,0xAD,0xA2,0xA4,0xB3);
OBFSTR_DECL(obs_j_string, 0xAD,0xA6,0xB1,0xA6,0xE8,0xAB,0xA6,0xA9,0xA0,0xE8,0x94,0xB3,0xB5,0xAE,0xA9,0xA0);
OBFSTR_DECL(obs_type_field, 0x93,0x9E,0x97,0x82);
OBFSTR_DECL(obs_valueof, 0xB1,0xA6,0xAB,0xB2,0xA2,0x88,0xA1);
OBFSTR_DECL(obs_sig_cls, 0xEF,0xEE,0x8B,0xAD,0xA6,0xB1,0xA6,0xE8,0xAB,0xA6,0xA9,0xA0,0xE8,0x84,0xAB,0xA6,0xB4,0xB4,0xFC);

/* Zero the full 8-byte register union before writing a sub-8-byte value
   to prevent stale upper bits from being misinterpreted by ART's GC. */
#define VMP_RSET_I(r, val) do { int32_t _vmp_tmp_i = (int32_t)(val); (r).j = 0; (r).i = _vmp_tmp_i; } while(0)
#define VMP_RSET_F(r, val) do { jfloat _vmp_tmp_f = (jfloat)(val); (r).j = 0; (r).f = _vmp_tmp_f; } while(0)

/* "M2vK7pQ9dL4" (len=11) — obfuscated magic */
OBFSTR_DECL(obs_vmp_magic, 0x8A,0xF5,0xB1,0x8C,0xF0,0xB7,0x96,0xFE,0xA3,0x8B,0xF3);
static uint8_t kVmpMagic[12];  /* filled at load time */
static const uint32_t kVmpVersion = 4;  /* v4: encrypted string pool */
static const uint32_t kVmpVersionV5 = 5;  /* v5: variable-length insns + per-build width/layout */

/* v5 width-class table mirroring _OP_WIDTH_BASE in vmp_compiler.py.
 * The loader uses this to derive the per-build width_table; the
 * dispatch loop uses it to advance the byte-offset PC after each insn. */
#define VMP_V5_W2  2
#define VMP_V5_W4  4
#define VMP_V5_W6  6
#define VMP_V5_W8  8
#define VMP_V5_W12 12
#define VMP_V5_W16 16

static int vmp_v5_layout_index_for_width(uint8_t w) {
    switch (w) {
        case VMP_V5_W2:  return VMP_V5_LAYOUT_W2;
        case VMP_V5_W4:  return VMP_V5_LAYOUT_W4;
        case VMP_V5_W6:  return VMP_V5_LAYOUT_W6;
        case VMP_V5_W8:  return VMP_V5_LAYOUT_W8;
        case VMP_V5_W12: return VMP_V5_LAYOUT_W12;
        case VMP_V5_W16: return VMP_V5_LAYOUT_W16;
        default: return -1;
    }
}

#define VMP_BINOP_REG0_SENTINEL ((int32_t)0x6E4B0001)
#define VMP_BINOP_LIT_ZERO_SENTINEL ((int32_t)0x6E4B0002)

typedef struct {
    const uint8_t *buf;
    size_t len;
    size_t off;
} blob_reader_t;

static uint32_t vmp_lfsr32(uint32_t state) {
    uint32_t lsb = state & 1U;
    state >>= 1U;
    if (lsb) state ^= 0xD0000001U;
    return state;
}

static void vmp_crypt_string(uint8_t *data, uint16_t len, uint32_t salt, uint32_t string_idx) {
    if (!data || len == 0) return;
    uint32_t seed = salt ^ ((string_idx + 1U) * 0x9E3779B1U);
    for (uint16_t i = 0; i < len; ++i) {
        seed = vmp_lfsr32(seed ? seed : 0xD00DF00DU);
        data[i] ^= (uint8_t)((seed >> ((i & 3U) * 8U)) & 0xFFU);
        data[i] ^= (uint8_t)((string_idx * 131U + (uint32_t)i * 17U + 0x5DU) & 0xFFU);
    }
}

/* ── v5 width / layout derivation ───────────────────────────────────────
 * Mirrors derive_v5_width_table() and derive_v5_layout_table() in
 * packer/vmp_compiler.py. The Python side is the source of truth; this
 * C implementation must produce bit-identical tables for the same seed
 * pair, otherwise the interpreter and compiler will disagree about
 * insn width and operand positions and the program will execute
 * garbage.
 *
 * The base width-per-real_op map is hard-coded below — same content as
 * _OP_WIDTH_BASE in vmp_compiler.py. Default for any unlisted op is W8.
 */

static uint8_t vmp_v5_base_width(int real_op) {
    switch (real_op) {
        /* W2 — zero-operand */
        case 0:   /* NOP */
        case 8:   /* RETURN_VOID */
            return VMP_V5_W2;

        /* W4 — 1-reg / 2-reg, no immediate */
        case 1: case 2: case 3:          /* MOVE / MOVE_WIDE / MOVE_OBJECT */
        case 4: case 5: case 6:          /* MOVE_RESULT / _WIDE / _OBJECT */
        case 7:                          /* MOVE_EXCEPTION */
        case 9: case 10: case 11:        /* RETURN / RETURN_WIDE / RETURN_OBJECT */
        case 16: case 17:                /* MONITOR_ENTER / MONITOR_EXIT */
        case 22:                         /* ARRAY_LENGTH */
        case 23:                         /* THROW */
        case 84: case 85: case 86: case 87:  /* NEG_INT / NOT_INT / NEG_LONG / NOT_LONG */
        case 88: case 89:                /* NEG_FLOAT / NEG_DOUBLE */
        case 90: case 91: case 92:       /* INT_TO_{LONG,FLOAT,DOUBLE} */
        case 93: case 94: case 95:       /* LONG_TO_{INT,FLOAT,DOUBLE} */
        case 96: case 97: case 98:       /* FLOAT_TO_{INT,LONG,DOUBLE} */
        case 99: case 100: case 101:     /* DOUBLE_TO_{INT,LONG,FLOAT} */
        case 102: case 103: case 104:    /* INT_TO_{BYTE,CHAR,SHORT} */
        case 160: case 161: case 162:
        case 163: case 164:              /* UNOP_ALIAS1..5 */
            return VMP_V5_W4;

        /* W12 — 64-bit immediates */
        case 13:    /* CONST_WIDE */
        case 147:   /* CONST_WIDE_HI32 */
            return VMP_V5_W12;

        /* W16 — invokes, switches, fill-array (uniform regardless of arity) */
        case 79: case 80: case 81: case 82: case 83:  /* INVOKE_{VIRTUAL,SUPER,DIRECT,STATIC,INTERFACE} */
        case 142: case 143:              /* PACKED_SWITCH / SPARSE_SWITCH */
        case 144:                        /* FILL_ARRAY_DATA */
        case 145:                        /* FILLED_NEW_ARRAY */
        case 146:                        /* INVOKE_ARGS (consumed by preceding invoke) */
        case 148: case 149:              /* INVOKE_CUSTOM / INVOKE_POLYMORPHIC */
            return VMP_V5_W16;

        default:
            return VMP_V5_W8;
    }
}

static void vmp_v5_derive_width_table(uint8_t out[256], uint32_t width_seed) {
    /* The Python implementation permutes ops *within* each width class
     * via LFSR, but since the per-real_op width never changes between
     * permutation slots in that algorithm, the final 256-entry table
     * just contains base_width(op) for each op. We replicate that
     * here. The width_seed parameter is reserved for future use where
     * the slot-permutation actually changes the wire encoding. */
    (void)width_seed;
    for (int op = 0; op < 256; ++op) {
        out[op] = vmp_v5_base_width(op);
    }
}

/* xorshift32 — matches the inline LFSR in derive_v5_layout_table(). */
static uint32_t vmp_v5_xorshift_next(uint32_t *state) {
    uint32_t s = *state;
    s ^= (s << 13);
    s ^= (s >> 17);
    s ^= (s << 5);
    *state = s ? s : 0x13579BDFU;
    return *state;
}

static void vmp_v5_derive_layouts(vmp_v5_layout_t out[VMP_V5_LAYOUT_COUNT], uint32_t layout_seed) {
    uint32_t state = layout_seed ? layout_seed : 0x13579BDFU;

    /* Per-class spec: number of 1-byte slots (excluding opcode, which
     * is anchored to byte 0), optional contiguous multi-byte payload
     * length. The order of 1-byte slot names is fixed:
     *   W2:  arg0
     *   W4:  dst, src1, pad
     *   W6:  dst                              + multi 4
     *   W8:  dst, src1, src2                  + multi 4
     *   W12: dst                              + multi 10
     *   W16: dst, nargs                       + multi 13
     */
    struct {
        uint8_t width;
        uint8_t single_count;
        uint8_t multi_len;
    } SPECS[] = {
        {VMP_V5_W2,  1, 0},
        {VMP_V5_W4,  3, 0},
        {VMP_V5_W6,  1, 4},
        {VMP_V5_W8,  3, 4},
        {VMP_V5_W12, 1, 10},
        {VMP_V5_W16, 2, 13},
    };

    for (int i = 0; i < VMP_V5_LAYOUT_COUNT; ++i) {
        uint8_t w = SPECS[i].width;
        uint8_t sc = SPECS[i].single_count;
        uint8_t ml = SPECS[i].multi_len;
        vmp_v5_layout_t *L = &out[i];
        memset(L, 0, sizeof(*L));
        L->valid = 1;

        uint8_t free_positions[16] = {0};
        int free_count = 0;
        for (int p = 1; p < w; ++p) free_positions[free_count++] = (uint8_t)p;

        if (ml == 0) {
            /* No multi-byte field — just permute single slots into free positions. */
            /* Fisher-Yates */
            for (int k = free_count - 1; k > 0; --k) {
                uint32_t r = vmp_v5_xorshift_next(&state);
                int j = (int)(r % (uint32_t)(k + 1));
                uint8_t t = free_positions[k];
                free_positions[k] = free_positions[j];
                free_positions[j] = t;
            }
            int p = 0;
            if (sc >= 1) L->dst_pos    = free_positions[p++];
            if (sc >= 2) L->src1_pos   = free_positions[p++];
            if (sc >= 3) L->src2_pos   = free_positions[p++];
        } else {
            /* Pick multi-byte start from valid range [1, w-ml]. */
            int valid_start_count = (int)(w - ml + 1 - 1);  /* inclusive [1..w-ml] */
            if (valid_start_count < 1) valid_start_count = 1;
            uint32_t r = vmp_v5_xorshift_next(&state);
            uint8_t multi_start = (uint8_t)(1 + (r % (uint32_t)valid_start_count));
            L->multi_start = multi_start;
            L->multi_len = ml;

            /* Remaining 1-byte positions: bytes [1..w-1] minus [multi_start..multi_start+ml-1]. */
            uint8_t remaining[16] = {0};
            int rcount = 0;
            for (int p = 1; p < w; ++p) {
                if (!(p >= multi_start && p < multi_start + ml)) {
                    remaining[rcount++] = (uint8_t)p;
                }
            }
            /* Fisher-Yates on remaining. */
            for (int k = rcount - 1; k > 0; --k) {
                uint32_t r2 = vmp_v5_xorshift_next(&state);
                int j = (int)(r2 % (uint32_t)(k + 1));
                uint8_t t = remaining[k];
                remaining[k] = remaining[j];
                remaining[j] = t;
            }
            int p = 0;
            if (sc >= 1) L->dst_pos   = remaining[p++];
            if (sc >= 2) L->src1_pos  = remaining[p++];  /* W8: dst, src1, src2; W16: dst, nargs */
            if (sc >= 3) L->src2_pos  = remaining[p++];
            /* W16: 'src1' slot here is actually nargs. We store it
             * in src1_pos and the dispatcher reads it from there. */
            if (w == VMP_V5_W16) {
                L->nargs_pos = L->src1_pos;
                L->src1_pos = 0;
            }
        }
    }
}

typedef enum {
    VMP_LAST_VOID = 0,
    VMP_LAST_INT,
    VMP_LAST_LONG,
    VMP_LAST_FLOAT,
    VMP_LAST_DOUBLE,
    VMP_LAST_OBJECT
} vmp_last_kind_t;

typedef struct {
    vmp_last_kind_t kind;
    union {
        jint i;
        jlong j;
        jfloat f;
        jdouble d;
        jobject l;
    } v;
} vmp_last_result_t;

typedef struct {
    int inited;
    jclass clsNumber;
    jclass clsBoolean;
    jclass clsCharacter;
    jclass clsByte;
    jclass clsShort;
    jclass clsInteger;
    jclass clsLong;
    jclass clsFloat;
    jclass clsDouble;

    jmethodID midNumberByteValue;
    jmethodID midNumberShortValue;
    jmethodID midNumberIntValue;
    jmethodID midNumberLongValue;
    jmethodID midNumberFloatValue;
    jmethodID midNumberDoubleValue;
    jmethodID midBooleanValue;
    jmethodID midCharacterValue;

    jmethodID midBooleanValueOf;
    jmethodID midCharacterValueOf;
    jmethodID midByteValueOf;
    jmethodID midShortValueOf;
    jmethodID midIntegerValueOf;
    jmethodID midLongValueOf;
    jmethodID midFloatValueOf;
    jmethodID midDoubleValueOf;
} vmp_box_cache_t;

static vmp_context_t g_vmp;
static jobject g_vmp_loader = NULL;      /* global ref */
static jmethodID g_mid_load_class = NULL;
static vmp_box_cache_t g_box;

/* Shell VMP: separate context for self-protection of the shell DEX. */
static vmp_context_t g_vmp_shell;
static jobject g_vmp_shell_loader = NULL;
static jmethodID g_mid_shell_load_class = NULL;

/*
 * Thread-local active context pointer.  The interpreter reads bytecode,
 * strings, opcode tables etc. through this indirection so both the payload
 * and shell VMP blobs can share the same interpreter code path.
 */
static _Thread_local vmp_context_t *_active_ctx = &g_vmp;

/* ── Class resolution cache ─────────────────────────────────────────── */
/*
 * Open-addressing hash table: class descriptor string → jclass (global ref).
 * Dramatically reduces FindClass calls during VMP execution.
 */
#define VMP_CLS_CACHE_SLOTS 64
#define VMP_CLS_CACHE_PROBE 4

typedef struct {
    char   *desc;  /* heap-allocated copy of the class descriptor */
    jclass  cls;   /* JNI global ref */
} vmp_cls_entry_t;

static vmp_cls_entry_t g_cls_cache[VMP_CLS_CACHE_SLOTS];

static uint32_t vmp_djb2(const char *s) {
    uint32_t h = 5381;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
        h = ((h << 5) + h) ^ *p;
    return h;
}

static jclass vmp_cls_cache_get(JNIEnv *env, const char *desc) {
    uint32_t h = vmp_djb2(desc);
    for (int i = 0; i < VMP_CLS_CACHE_PROBE; i++) {
        uint32_t slot = (h + (uint32_t)i) % VMP_CLS_CACHE_SLOTS;
        if (!g_cls_cache[slot].desc) return NULL;
        if (strcmp(g_cls_cache[slot].desc, desc) == 0)
            return (*env)->NewLocalRef(env, g_cls_cache[slot].cls);
    }
    return NULL;
}

static void vmp_cls_cache_put(JNIEnv *env, const char *desc, jclass local) {
    jclass g = (*env)->NewGlobalRef(env, local);
    if (!g) return;
    uint32_t h = vmp_djb2(desc);
    for (int i = 0; i < VMP_CLS_CACHE_PROBE; i++) {
        uint32_t slot = (h + (uint32_t)i) % VMP_CLS_CACHE_SLOTS;
        if (!g_cls_cache[slot].desc) {
            g_cls_cache[slot].desc = strdup(desc);
            if (!g_cls_cache[slot].desc) {
                (*env)->DeleteGlobalRef(env, g);
                return;
            }
            g_cls_cache[slot].cls = g;
            return;
        }
    }
    (*env)->DeleteGlobalRef(env, g);  /* cache full, discard */
}

static void vmp_cls_cache_clear(JNIEnv *env) {
    for (int i = 0; i < VMP_CLS_CACHE_SLOTS; i++) {
        if (g_cls_cache[i].desc) {
            if (env && g_cls_cache[i].cls)
                (*env)->DeleteGlobalRef(env, g_cls_cache[i].cls);
            free(g_cls_cache[i].desc);
            g_cls_cache[i].desc = NULL;
            g_cls_cache[i].cls = NULL;
        }
    }
}

/* ── Field ID resolution cache ─────────────────────────────────────── */
/*
 * Keyed by (ref_ptr, is_static). ref_ptr is a pointer into g_vmp.strings[]
 * which is stable for the VMP context lifetime. Avoids repeated
 * vmp_parse_field_ref + vmp_resolve_class + GetFieldID per access.
 */
#define VMP_FID_CACHE_SLOTS 128
#define VMP_FID_CACHE_PROBE 4

typedef struct {
    const char *ref;     /* pointer into g_vmp.strings (identity key) */
    uint8_t    is_static;
    jclass     cls;      /* JNI global ref */
    jfieldID   fid;
} vmp_fid_entry_t;

static vmp_fid_entry_t g_fid_cache[VMP_FID_CACHE_SLOTS];

static uint32_t vmp_ptr_hash(const void *p, int extra) {
    uintptr_t v = (uintptr_t)p;
    return (uint32_t)((v >> 3) ^ (v >> 17)) ^ (uint32_t)extra;
}

static jfieldID vmp_fid_cache_get(JNIEnv *env, const char *ref, int is_static, jclass *out_cls) {
    uint32_t h = vmp_ptr_hash(ref, is_static);
    for (int i = 0; i < VMP_FID_CACHE_PROBE; i++) {
        uint32_t slot = (h + (uint32_t)i) % VMP_FID_CACHE_SLOTS;
        if (!g_fid_cache[slot].ref) return NULL;
        if (g_fid_cache[slot].ref == ref && g_fid_cache[slot].is_static == (uint8_t)is_static) {
            *out_cls = (*env)->NewLocalRef(env, g_fid_cache[slot].cls);
            return g_fid_cache[slot].fid;
        }
    }
    return NULL;
}

static void vmp_fid_cache_put(JNIEnv *env, const char *ref, int is_static, jclass cls, jfieldID fid) {
    jclass g = (*env)->NewGlobalRef(env, cls);
    if (!g) return;
    uint32_t h = vmp_ptr_hash(ref, is_static);
    for (int i = 0; i < VMP_FID_CACHE_PROBE; i++) {
        uint32_t slot = (h + (uint32_t)i) % VMP_FID_CACHE_SLOTS;
        if (!g_fid_cache[slot].ref) {
            g_fid_cache[slot].ref = ref;
            g_fid_cache[slot].is_static = (uint8_t)is_static;
            g_fid_cache[slot].cls = g;
            g_fid_cache[slot].fid = fid;
            return;
        }
    }
    (*env)->DeleteGlobalRef(env, g);
}

static void vmp_fid_cache_clear(JNIEnv *env) {
    for (int i = 0; i < VMP_FID_CACHE_SLOTS; i++) {
        if (g_fid_cache[i].ref) {
            if (env && g_fid_cache[i].cls)
                (*env)->DeleteGlobalRef(env, g_fid_cache[i].cls);
            g_fid_cache[i].ref = NULL;
            g_fid_cache[i].cls = NULL;
            g_fid_cache[i].fid = NULL;
        }
    }
}

/* ── Method ID resolution cache ────────────────────────────────────── */
#define VMP_MID_CACHE_SLOTS 128
#define VMP_MID_CACHE_PROBE 4

typedef struct {
    const char *ref;
    uint8_t    is_static;
    jclass     cls;      /* JNI global ref */
    jmethodID  mid;
} vmp_mid_entry_t;

static vmp_mid_entry_t g_mid_cache[VMP_MID_CACHE_SLOTS];

static jmethodID vmp_mid_cache_get(JNIEnv *env, const char *ref, int is_static, jclass *out_cls) {
    uint32_t h = vmp_ptr_hash(ref, is_static);
    for (int i = 0; i < VMP_MID_CACHE_PROBE; i++) {
        uint32_t slot = (h + (uint32_t)i) % VMP_MID_CACHE_SLOTS;
        if (!g_mid_cache[slot].ref) return NULL;
        if (g_mid_cache[slot].ref == ref && g_mid_cache[slot].is_static == (uint8_t)is_static) {
            *out_cls = (*env)->NewLocalRef(env, g_mid_cache[slot].cls);
            return g_mid_cache[slot].mid;
        }
    }
    return NULL;
}

static void vmp_mid_cache_put(JNIEnv *env, const char *ref, int is_static, jclass cls, jmethodID mid) {
    jclass g = (*env)->NewGlobalRef(env, cls);
    if (!g) return;
    uint32_t h = vmp_ptr_hash(ref, is_static);
    for (int i = 0; i < VMP_MID_CACHE_PROBE; i++) {
        uint32_t slot = (h + (uint32_t)i) % VMP_MID_CACHE_SLOTS;
        if (!g_mid_cache[slot].ref) {
            g_mid_cache[slot].ref = ref;
            g_mid_cache[slot].is_static = (uint8_t)is_static;
            g_mid_cache[slot].cls = g;
            g_mid_cache[slot].mid = mid;
            return;
        }
    }
    (*env)->DeleteGlobalRef(env, g);
}

static void vmp_mid_cache_clear(JNIEnv *env) {
    for (int i = 0; i < VMP_MID_CACHE_SLOTS; i++) {
        if (g_mid_cache[i].ref) {
            if (env && g_mid_cache[i].cls)
                (*env)->DeleteGlobalRef(env, g_mid_cache[i].cls);
            g_mid_cache[i].ref = NULL;
            g_mid_cache[i].cls = NULL;
            g_mid_cache[i].mid = NULL;
        }
    }
}

/* ── Branch prediction hints ──────────────────────────────────────── */
#if defined(__GNUC__) || defined(__clang__)
#define VMP_LIKELY(x)   __builtin_expect(!!(x), 1)
#define VMP_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define VMP_LIKELY(x)   (x)
#define VMP_UNLIKELY(x) (x)
#endif

/* --------------------------------------------------------------------- */
/* Reader helpers                                                        */
/* --------------------------------------------------------------------- */

static int rd_bytes(blob_reader_t *r, void *out, size_t n) {
    if (!r || !out || r->off + n > r->len) return -1;
    memcpy(out, r->buf + r->off, n);
    r->off += n;
    return 0;
}

static int rd_u16(blob_reader_t *r, uint16_t *out) {
    uint8_t b[2];
    if (rd_bytes(r, b, 2) != 0) return -1;
    *out = (uint16_t) (b[0] | ((uint16_t) b[1] << 8));
    return 0;
}

static int rd_u32(blob_reader_t *r, uint32_t *out) {
    uint8_t b[4];
    if (rd_bytes(r, b, 4) != 0) return -1;
    *out = (uint32_t) b[0] |
           ((uint32_t) b[1] << 8) |
           ((uint32_t) b[2] << 16) |
           ((uint32_t) b[3] << 24);
    return 0;
}

static int rd_i32(blob_reader_t *r, int32_t *out) {
    uint32_t v;
    if (rd_u32(r, &v) != 0) return -1;
    *out = (int32_t) v;
    return 0;
}

/* --------------------------------------------------------------------- */
/* Small utilities                                                       */
/* --------------------------------------------------------------------- */

static int vmp_desc_is_ref(const char *desc) {
    if (!desc || !desc[0]) return 0;
    return desc[0] == 'L' || desc[0] == '[';
}

static int vmp_desc_width_words(const char *desc) {
    if (!desc || !desc[0]) return 1;
    return (desc[0] == 'J' || desc[0] == 'D') ? 2 : 1;
}

static int vmp_clamp_tier(int tier) {
    if (tier == VMP_TIER_COMPAT || tier == VMP_TIER_STRONG) {
        return tier;
    }
    return VMP_TIER_LIGHT;
}

static const char *vmp_tier_name(int tier) {
    switch (vmp_clamp_tier(tier)) {
        case VMP_TIER_COMPAT: return "compat";
        case VMP_TIER_STRONG: return "strong";
        default: return "light";
    }
}

static const char *vmp_desc_end(const char *p) {
    if (!p || !*p) return p;
    if (*p == '[') {
        while (*p == '[') p++;
        if (*p == 'L') {
            while (*p && *p != ';') p++;
            if (*p == ';') p++;
            return p;
        }
        if (*p) p++;
        return p;
    }
    if (*p == 'L') {
        while (*p && *p != ';') p++;
        if (*p == ';') p++;
        return p;
    }
    return p + 1;
}

static char *vmp_strdup_range(const char *s, size_t n) {
    char *p = (char *) malloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n);
    p[n] = '\0';
    return p;
}

static void vmp_throw(JNIEnv *env, const char *klass, const char *msg) {
    if (!env) return;
    jclass ex = (*env)->FindClass(env, klass);
    if (ex) {
        (*env)->ThrowNew(env, ex, msg ? msg : "");
        (*env)->DeleteLocalRef(env, ex);
    }
}

static void vmp_throw_runtime(JNIEnv *env, const char *msg) {
    OBFSTR_USE(_cls, obs_j_rte, 26);
    vmp_throw(env, _cls, msg);
}

static void vmp_throw_arith(JNIEnv *env, const char *msg) {
    OBFSTR_USE(_cls, obs_j_arith, 29);
    vmp_throw(env, _cls, msg);
}

static void vmp_throw_npe(JNIEnv *env, const char *msg) {
    OBFSTR_USE(_cls, obs_j_npe, 30);
    vmp_throw(env, _cls, msg);
}

static const char *vmp_method_sig(const vmp_method_t *m) {
    if (!m) return NULL;
    if (m->method_sig_idx >= _active_ctx->string_count) return NULL;
    return _active_ctx->strings[m->method_sig_idx];
}

static const char *vmp_pool_get(uint32_t idx) {
    if (idx >= _active_ctx->string_count) return NULL;
    return _active_ctx->strings[idx];
}

/* --------------------------------------------------------------------- */
/* Class resolution                                                      */
/* --------------------------------------------------------------------- */

static char *vmp_desc_to_slash_name(const char *desc) {
    if (!desc) return NULL;
    size_t n = strlen(desc);
    if (n >= 2 && desc[0] == 'L' && desc[n - 1] == ';') {
        return vmp_strdup_range(desc + 1, n - 2);  /* java/lang/String */
    }
    if (desc[0] == '[') {
        return strdup(desc);                        /* [Ljava/lang/String; */
    }
    return strdup(desc);
}

static char *vmp_desc_to_dot_name(const char *desc) {
    if (!desc) return NULL;
    size_t n = strlen(desc);
    if (n >= 2 && desc[0] == 'L' && desc[n - 1] == ';') {
        char *out = vmp_strdup_range(desc + 1, n - 2); /* java/lang/String */
        if (!out) return NULL;
        for (char *p = out; *p; ++p) {
            if (*p == '/') *p = '.';
        }
        return out;
    }
    /* For arrays or primitive descriptors, caller should prefer FindClass path. */
    return strdup(desc);
}

static jclass vmp_primitive_class(JNIEnv *env, char c) {
    /* Decrypt wrapper class name on the stack */
    char _w[20]; /* max len = "java/lang/Character" = 19 + NUL */
    int wlen = 0;
    switch (c) {
        case 'V': obs_j_void_dec(_w, 14); wlen = 14; break;
        case 'Z': obs_j_boolean_dec(_w, 17); wlen = 17; break;
        case 'B': obs_j_byte_dec(_w, 14); wlen = 14; break;
        case 'C': obs_j_char_dec(_w, 19); wlen = 19; break;
        case 'S': obs_j_short_dec(_w, 15); wlen = 15; break;
        case 'I': obs_j_integer_dec(_w, 17); wlen = 17; break;
        case 'J': obs_j_long_dec(_w, 14); wlen = 14; break;
        case 'F': obs_j_float_dec(_w, 15); wlen = 15; break;
        case 'D': obs_j_double_dec(_w, 16); wlen = 16; break;
        default: return NULL;
    }
    _w[wlen] = '\0';
    jclass clsWrapper = (*env)->FindClass(env, _w);
    if (!clsWrapper) return NULL;
    OBFSTR_USE(_tf, obs_type_field, 4);
    OBFSTR_USE(_sc, obs_sig_cls, 19);
    jfieldID fidType = (*env)->GetStaticFieldID(env, clsWrapper, _tf, _sc);
    if (!fidType) {
        (*env)->DeleteLocalRef(env, clsWrapper);
        return NULL;
    }
    jobject typeObj = (*env)->GetStaticObjectField(env, clsWrapper, fidType);
    (*env)->DeleteLocalRef(env, clsWrapper);
    return (jclass) typeObj;
}

static jclass vmp_resolve_class(JNIEnv *env, const char *desc) {
    if (!env || !desc || !desc[0]) return NULL;

    /* Primitive type descriptor — not cached. */
    if (!vmp_desc_is_ref(desc) && desc[1] == '\0') {
        return vmp_primitive_class(env, desc[0]);
    }

    /* ── Cache lookup ── */
    jclass cached = vmp_cls_cache_get(env, desc);
    if (cached) return cached;

    /* First try FindClass (works for boot + often payload when called from payload-native context). */
    char *slash = vmp_desc_to_slash_name(desc);
    if (!slash) return NULL;
    jclass cls = (*env)->FindClass(env, slash);
    free(slash);
    if (cls) {
        vmp_cls_cache_put(env, desc, cls);
        return cls;
    }

    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
    }

    /* Fallback: payload ClassLoader.loadClass(binaryName). */
    if (g_vmp_loader && g_mid_load_class && desc[0] == 'L') {
        char *dot = vmp_desc_to_dot_name(desc);
        if (!dot) return NULL;
        jstring jName = (*env)->NewStringUTF(env, dot);
        free(dot);
        if (!jName) return NULL;
        jobject out = (*env)->CallObjectMethod(env, g_vmp_loader, g_mid_load_class, jName);
        (*env)->DeleteLocalRef(env, jName);
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);
            return NULL;
        }
        if (out) vmp_cls_cache_put(env, desc, (jclass) out);
        return (jclass) out;
    }

    return NULL;
}

/* --------------------------------------------------------------------- */
/* Box / unbox                                                           */
/* --------------------------------------------------------------------- */

static int vmp_box_cache_init(JNIEnv *env) {
    if (g_box.inited) return 0;

    jclass c = NULL;

    /* Decrypt all class names once on the stack */
    OBFSTR_USE(cn_number,    obs_j_number,    16);
    OBFSTR_USE(cn_boolean,   obs_j_boolean,   17);
    OBFSTR_USE(cn_char,      obs_j_char,      19);
    OBFSTR_USE(cn_byte,      obs_j_byte,      14);
    OBFSTR_USE(cn_short,     obs_j_short,     15);
    OBFSTR_USE(cn_integer,   obs_j_integer,   17);
    OBFSTR_USE(cn_long,      obs_j_long,      14);
    OBFSTR_USE(cn_float,     obs_j_float,     15);
    OBFSTR_USE(cn_double,    obs_j_double,    16);

#define INIT_CLS(dst, name)                                    \
    do {                                                       \
        c = (*env)->FindClass(env, name);                      \
        if (!c) return -1;                                     \
        dst = (jclass)(*env)->NewGlobalRef(env, c);            \
        (*env)->DeleteLocalRef(env, c);                        \
        if (!dst) return -1;                                   \
    } while (0)

    INIT_CLS(g_box.clsNumber,    cn_number);
    INIT_CLS(g_box.clsBoolean,   cn_boolean);
    INIT_CLS(g_box.clsCharacter, cn_char);
    INIT_CLS(g_box.clsByte,      cn_byte);
    INIT_CLS(g_box.clsShort,     cn_short);
    INIT_CLS(g_box.clsInteger,   cn_integer);
    INIT_CLS(g_box.clsLong,      cn_long);
    INIT_CLS(g_box.clsFloat,     cn_float);
    INIT_CLS(g_box.clsDouble,    cn_double);

#undef INIT_CLS

    g_box.midNumberByteValue = (*env)->GetMethodID(env, g_box.clsNumber, "byteValue", "()B");
    g_box.midNumberShortValue = (*env)->GetMethodID(env, g_box.clsNumber, "shortValue", "()S");
    g_box.midNumberIntValue = (*env)->GetMethodID(env, g_box.clsNumber, "intValue", "()I");
    g_box.midNumberLongValue = (*env)->GetMethodID(env, g_box.clsNumber, "longValue", "()J");
    g_box.midNumberFloatValue = (*env)->GetMethodID(env, g_box.clsNumber, "floatValue", "()F");
    g_box.midNumberDoubleValue = (*env)->GetMethodID(env, g_box.clsNumber, "doubleValue", "()D");
    g_box.midBooleanValue = (*env)->GetMethodID(env, g_box.clsBoolean, "booleanValue", "()Z");
    g_box.midCharacterValue = (*env)->GetMethodID(env, g_box.clsCharacter, "charValue", "()C");

    /* Build valueOf signatures dynamically — no class name string literals */
    OBFSTR_USE(s_valueOf, obs_valueof, 7);
    char sig[64];

#define VALUEOF_SIG(prim, cls_name) \
    snprintf(sig, sizeof(sig), "(%c)L%s;", prim, cls_name)

    VALUEOF_SIG('Z', cn_boolean);
    g_box.midBooleanValueOf = (*env)->GetStaticMethodID(env, g_box.clsBoolean, s_valueOf, sig);
    VALUEOF_SIG('C', cn_char);
    g_box.midCharacterValueOf = (*env)->GetStaticMethodID(env, g_box.clsCharacter, s_valueOf, sig);
    VALUEOF_SIG('B', cn_byte);
    g_box.midByteValueOf = (*env)->GetStaticMethodID(env, g_box.clsByte, s_valueOf, sig);
    VALUEOF_SIG('S', cn_short);
    g_box.midShortValueOf = (*env)->GetStaticMethodID(env, g_box.clsShort, s_valueOf, sig);
    VALUEOF_SIG('I', cn_integer);
    g_box.midIntegerValueOf = (*env)->GetStaticMethodID(env, g_box.clsInteger, s_valueOf, sig);
    VALUEOF_SIG('J', cn_long);
    g_box.midLongValueOf = (*env)->GetStaticMethodID(env, g_box.clsLong, s_valueOf, sig);
    VALUEOF_SIG('F', cn_float);
    g_box.midFloatValueOf = (*env)->GetStaticMethodID(env, g_box.clsFloat, s_valueOf, sig);
    VALUEOF_SIG('D', cn_double);
    g_box.midDoubleValueOf = (*env)->GetStaticMethodID(env, g_box.clsDouble, s_valueOf, sig);

#undef VALUEOF_SIG

    if (!g_box.midNumberByteValue || !g_box.midNumberShortValue ||
        !g_box.midNumberIntValue || !g_box.midNumberLongValue ||
        !g_box.midNumberFloatValue || !g_box.midNumberDoubleValue ||
        !g_box.midBooleanValue || !g_box.midCharacterValue ||
        !g_box.midBooleanValueOf || !g_box.midCharacterValueOf ||
        !g_box.midByteValueOf || !g_box.midShortValueOf ||
        !g_box.midIntegerValueOf || !g_box.midLongValueOf ||
        !g_box.midFloatValueOf || !g_box.midDoubleValueOf) {
        return -1;
    }

    g_box.inited = 1;
    return 0;
}

static int vmp_unbox_to_reg(JNIEnv *env, jobject obj, const char *desc, vmp_reg_t *out) {
    if (!desc || !desc[0] || !out) return -1;
    memset(out, 0, sizeof(*out));

    if (vmp_desc_is_ref(desc)) {
        out->l = obj;
        return 0;
    }

    if (vmp_box_cache_init(env) != 0) return -1;

    if (obj == NULL) {
        /* Java bridge may pass null for primitive; default to zero. */
        return 0;
    }

    switch (desc[0]) {
        case 'Z':
            out->i = (jint) ((*env)->CallBooleanMethod(env, obj, g_box.midBooleanValue) ? 1 : 0);
            break;
        case 'B':
            out->i = (jint) (*env)->CallByteMethod(env, obj, g_box.midNumberByteValue);
            break;
        case 'C':
            out->i = (jint) (*env)->CallCharMethod(env, obj, g_box.midCharacterValue);
            break;
        case 'S':
            out->i = (jint) (*env)->CallShortMethod(env, obj, g_box.midNumberShortValue);
            break;
        case 'I':
            out->i = (jint) (*env)->CallIntMethod(env, obj, g_box.midNumberIntValue);
            break;
        case 'J':
            out->j = (jlong) (*env)->CallLongMethod(env, obj, g_box.midNumberLongValue);
            break;
        case 'F':
            out->f = (jfloat) (*env)->CallFloatMethod(env, obj, g_box.midNumberFloatValue);
            break;
        case 'D':
            out->d = (jdouble) (*env)->CallDoubleMethod(env, obj, g_box.midNumberDoubleValue);
            break;
        default:
            return -1;
    }
    return (*env)->ExceptionCheck(env) ? -1 : 0;
}

static jobject vmp_box_from_reg(JNIEnv *env, const char *ret_desc, const vmp_reg_t *reg) {
    if (!ret_desc || !ret_desc[0] || !reg) return NULL;

    if (ret_desc[0] == 'V') return NULL;
    if (vmp_desc_is_ref(ret_desc)) return reg->l;

    if (vmp_box_cache_init(env) != 0) return NULL;

    switch (ret_desc[0]) {
        case 'Z':
            return (*env)->CallStaticObjectMethod(env, g_box.clsBoolean, g_box.midBooleanValueOf, (jboolean) (reg->i != 0));
        case 'B':
            return (*env)->CallStaticObjectMethod(env, g_box.clsByte, g_box.midByteValueOf, (jbyte) reg->i);
        case 'C':
            return (*env)->CallStaticObjectMethod(env, g_box.clsCharacter, g_box.midCharacterValueOf, (jchar) reg->i);
        case 'S':
            return (*env)->CallStaticObjectMethod(env, g_box.clsShort, g_box.midShortValueOf, (jshort) reg->i);
        case 'I':
            return (*env)->CallStaticObjectMethod(env, g_box.clsInteger, g_box.midIntegerValueOf, (jint) reg->i);
        case 'J':
            return (*env)->CallStaticObjectMethod(env, g_box.clsLong, g_box.midLongValueOf, (jlong) reg->j);
        case 'F':
            return (*env)->CallStaticObjectMethod(env, g_box.clsFloat, g_box.midFloatValueOf, (jfloat) reg->f);
        case 'D':
            return (*env)->CallStaticObjectMethod(env, g_box.clsDouble, g_box.midDoubleValueOf, (jdouble) reg->d);
        default:
            return NULL;
    }
}

/* --------------------------------------------------------------------- */
/* Ref parsing                                                           */
/* --------------------------------------------------------------------- */

static int vmp_parse_method_ref(
        const char *ref,
        char **out_class_desc,
        char **out_name,
        char **out_sig) {
    if (!ref || !out_class_desc || !out_name || !out_sig) return -1;
    *out_class_desc = NULL;
    *out_name = NULL;
    *out_sig = NULL;

    const char *arrow = strstr(ref, "->");
    if (!arrow) return -1;
    const char *paren = strchr(arrow + 2, '(');
    if (!paren) return -1;

    *out_class_desc = vmp_strdup_range(ref, (size_t) (arrow - ref));
    *out_name = vmp_strdup_range(arrow + 2, (size_t) (paren - (arrow + 2)));
    *out_sig = strdup(paren);
    if (!*out_class_desc || !*out_name || !*out_sig) {
        free(*out_class_desc);
        free(*out_name);
        free(*out_sig);
        *out_class_desc = NULL;
        *out_name = NULL;
        *out_sig = NULL;
        return -1;
    }
    return 0;
}

static int vmp_parse_field_ref(
        const char *ref,
        char **out_class_desc,
        char **out_name,
        char **out_type_desc) {
    if (!ref || !out_class_desc || !out_name || !out_type_desc) return -1;
    *out_class_desc = NULL;
    *out_name = NULL;
    *out_type_desc = NULL;

    const char *arrow = strstr(ref, "->");
    if (!arrow) return -1;
    const char *colon = strchr(arrow + 2, ':');
    if (!colon) return -1;

    *out_class_desc = vmp_strdup_range(ref, (size_t) (arrow - ref));
    *out_name = vmp_strdup_range(arrow + 2, (size_t) (colon - (arrow + 2)));
    *out_type_desc = strdup(colon + 1);
    if (!*out_class_desc || !*out_name || !*out_type_desc) {
        free(*out_class_desc);
        free(*out_name);
        free(*out_type_desc);
        *out_class_desc = NULL;
        *out_name = NULL;
        *out_type_desc = NULL;
        return -1;
    }
    return 0;
}

/* --------------------------------------------------------------------- */
/* Invoke helpers                                                        */
/* --------------------------------------------------------------------- */

static int vmp_collect_invoke_regs(
        const vmp_insn_t *args_insn,
        int arg_words,
        uint8_t *out_regs,
        int out_cap) {
    if (!args_insn || !out_regs || out_cap <= 0 || arg_words < 0) return -1;
    if (arg_words > out_cap) return -1;

    if (args_insn->imm == 1) {
        /* /range mode: start register in dst|src1<<8 */
        int start = (int) args_insn->dst | ((int) args_insn->src1 << 8);
        for (int i = 0; i < arg_words; ++i) {
            out_regs[i] = (uint8_t) (start + i);
        }
        return 0;
    }

    /* 35c mode: up to 5 register words packed as C, D, E, F, G */
    uint8_t tmp[5];
    tmp[0] = args_insn->dst;
    tmp[1] = args_insn->src1;
    tmp[2] = args_insn->src2;
    tmp[3] = (uint8_t) (args_insn->imm & 0xFF);
    tmp[4] = (uint8_t) ((args_insn->imm >> 8) & 0xFF);

    if (arg_words > 5) return -1;
    for (int i = 0; i < arg_words; ++i) {
        out_regs[i] = tmp[i];
    }
    return 0;
}

static int vmp_build_call_args(
        JNIEnv *env,
        const char *sig,
        const uint8_t *invoke_word_regs,
        int invoke_word_count,
        int is_static,
        vmp_reg_t regs[VMP_MAX_REGS],
        jobject *out_receiver,
        jvalue **out_jargs,
        int *out_jargc,
        const char **out_ret_desc) {
    if (!sig || !invoke_word_regs || !out_receiver || !out_jargs || !out_jargc || !out_ret_desc) {
        return -1;
    }

    const char *lp = strchr(sig, '(');
    const char *rp = strchr(sig, ')');
    if (!lp || !rp || rp < lp) return -1;

    const char *ret_desc = rp + 1;
    if (!*ret_desc) ret_desc = "V";
    *out_ret_desc = ret_desc;

    int param_count = 0;
    const char *p = lp + 1;
    while (p < rp && *p) {
        const char *e = vmp_desc_end(p);
        if (!e || e <= p || e > rp) return -1;
        param_count++;
        p = e;
    }

    jvalue *jargs = NULL;
    if (param_count > 0) {
        jargs = (jvalue *) calloc((size_t) param_count, sizeof(jvalue));
        if (!jargs) return -1;
    }

    int word_pos = 0;
    jobject receiver = NULL;
    if (!is_static) {
        if (invoke_word_count <= 0) {
            free(jargs);
            return -1;
        }
        uint8_t rcv_reg = invoke_word_regs[0];
        if (rcv_reg >= VMP_MAX_REGS) {
            free(jargs);
            return -1;
        }
        receiver = regs[rcv_reg].l;
        word_pos = 1;
    }

    int ai = 0;
    p = lp + 1;
    while (p < rp && *p) {
        const char *e = vmp_desc_end(p);
        if (!e || e <= p || e > rp) {
            free(jargs);
            return -1;
        }

        if (word_pos >= invoke_word_count) {
            free(jargs);
            return -1;
        }
        uint8_t reg_idx = invoke_word_regs[word_pos];
        if (reg_idx >= VMP_MAX_REGS) {
            free(jargs);
            return -1;
        }
        const vmp_reg_t *r = &regs[reg_idx];

        switch (p[0]) {
            case 'Z': jargs[ai].z = (jboolean) (r->i != 0); break;
            case 'B': jargs[ai].b = (jbyte) r->i; break;
            case 'C': jargs[ai].c = (jchar) r->i; break;
            case 'S': jargs[ai].s = (jshort) r->i; break;
            case 'I': jargs[ai].i = (jint) r->i; break;
            case 'J': jargs[ai].j = (jlong) r->j; break;
            case 'F': jargs[ai].f = (jfloat) r->f; break;
            case 'D': jargs[ai].d = (jdouble) r->d; break;
            default:
                jargs[ai].l = r->l;
                break;
        }

        word_pos += vmp_desc_width_words(p);
        ai++;
        p = e;
    }

    *out_receiver = receiver;
    *out_jargs = jargs;
    *out_jargc = param_count;
    (void) env;
    return 0;
}

static int vmp_invoke_ref(
        JNIEnv *env,
        int invoke_op,
        const char *method_ref,
        const uint8_t *invoke_word_regs,
        int invoke_word_count,
        vmp_reg_t regs[VMP_MAX_REGS],
        vmp_last_result_t *last_result) {
    if (!env || !method_ref || !invoke_word_regs || !last_result) return -1;

    int is_static = (invoke_op == VMP_INVOKE_STATIC);
    int use_nonvirtual = (invoke_op == VMP_INVOKE_DIRECT || invoke_op == VMP_INVOKE_SUPER);

    char *class_desc = NULL;
    char *name = NULL;
    char *sig = NULL;
    jclass cls = NULL;
    jvalue *jargs = NULL;
    jobject receiver = NULL;
    const char *ret_desc = "V";
    jmethodID mid = NULL;
    int argc = 0;
    int rc = -1;

    /* Fast path: check method ID cache */
    mid = vmp_mid_cache_get(env, method_ref, is_static, &cls);
    if (VMP_LIKELY(mid != NULL)) {
        /* Extract sig directly from method_ref without alloc:
         * format is "Lclass;->name(params)ret" — sig starts at '(' */
        const char *arrow = strstr(method_ref, "->");
        const char *fast_sig = arrow ? strchr(arrow + 2, '(') : NULL;
        if (VMP_UNLIKELY(!fast_sig)) goto slow_path;

        if (vmp_build_call_args(env, fast_sig, invoke_word_regs, invoke_word_count, is_static, regs,
                                &receiver, &jargs, &argc, &ret_desc) != 0) {
            goto done;
        }
        if (!is_static && VMP_UNLIKELY(!receiver)) {
            vmp_throw_npe(env, "invoke on null receiver");
            goto done;
        }
        goto do_call;
    }

slow_path:
    /* Slow path: full resolution */
    if (vmp_parse_method_ref(method_ref, &class_desc, &name, &sig) != 0) {
        goto done;
    }

    cls = vmp_resolve_class(env, class_desc);
    if (!cls) {
        goto done;
    }

    if (vmp_build_call_args(env, sig, invoke_word_regs, invoke_word_count, is_static, regs,
                            &receiver, &jargs, &argc, &ret_desc) != 0) {
        goto done;
    }

    if (is_static) {
        mid = (*env)->GetStaticMethodID(env, cls, name, sig);
    } else {
        mid = (*env)->GetMethodID(env, cls, name, sig);
        if (!receiver) {
            vmp_throw_npe(env, "invoke on null receiver");
            goto done;
        }
    }
    if (!mid) goto done;
    vmp_mid_cache_put(env, method_ref, is_static, cls, mid);

do_call:
    memset(last_result, 0, sizeof(*last_result));
    last_result->kind = VMP_LAST_VOID;

    switch (ret_desc[0]) {
        case 'V':
            if (is_static) {
                (*env)->CallStaticVoidMethodA(env, cls, mid, jargs);
            } else if (use_nonvirtual) {
                (*env)->CallNonvirtualVoidMethodA(env, receiver, cls, mid, jargs);
            } else {
                (*env)->CallVoidMethodA(env, receiver, mid, jargs);
            }
            last_result->kind = VMP_LAST_VOID;
            break;
        case 'J':
            if (is_static) {
                last_result->v.j = (*env)->CallStaticLongMethodA(env, cls, mid, jargs);
            } else if (use_nonvirtual) {
                last_result->v.j = (*env)->CallNonvirtualLongMethodA(env, receiver, cls, mid, jargs);
            } else {
                last_result->v.j = (*env)->CallLongMethodA(env, receiver, mid, jargs);
            }
            last_result->kind = VMP_LAST_LONG;
            break;
        case 'D':
            if (is_static) {
                last_result->v.d = (*env)->CallStaticDoubleMethodA(env, cls, mid, jargs);
            } else if (use_nonvirtual) {
                last_result->v.d = (*env)->CallNonvirtualDoubleMethodA(env, receiver, cls, mid, jargs);
            } else {
                last_result->v.d = (*env)->CallDoubleMethodA(env, receiver, mid, jargs);
            }
            last_result->kind = VMP_LAST_DOUBLE;
            break;
        case 'F':
            if (is_static) {
                last_result->v.f = (*env)->CallStaticFloatMethodA(env, cls, mid, jargs);
            } else if (use_nonvirtual) {
                last_result->v.f = (*env)->CallNonvirtualFloatMethodA(env, receiver, cls, mid, jargs);
            } else {
                last_result->v.f = (*env)->CallFloatMethodA(env, receiver, mid, jargs);
            }
            last_result->kind = VMP_LAST_FLOAT;
            break;
        case '[':
        case 'L':
            if (is_static) {
                last_result->v.l = (*env)->CallStaticObjectMethodA(env, cls, mid, jargs);
            } else if (use_nonvirtual) {
                last_result->v.l = (*env)->CallNonvirtualObjectMethodA(env, receiver, cls, mid, jargs);
            } else {
                last_result->v.l = (*env)->CallObjectMethodA(env, receiver, mid, jargs);
            }
            last_result->kind = VMP_LAST_OBJECT;
            break;
        case 'Z':
            /* JNI requires type-correct CallXxxMethod for Xcheck:jni */
            if (is_static) {
                last_result->v.i = (jint)(*env)->CallStaticBooleanMethodA(env, cls, mid, jargs);
            } else if (use_nonvirtual) {
                last_result->v.i = (jint)(*env)->CallNonvirtualBooleanMethodA(env, receiver, cls, mid, jargs);
            } else {
                last_result->v.i = (jint)(*env)->CallBooleanMethodA(env, receiver, mid, jargs);
            }
            last_result->kind = VMP_LAST_INT;
            break;
        case 'B':
            if (is_static) {
                last_result->v.i = (jint)(*env)->CallStaticByteMethodA(env, cls, mid, jargs);
            } else if (use_nonvirtual) {
                last_result->v.i = (jint)(*env)->CallNonvirtualByteMethodA(env, receiver, cls, mid, jargs);
            } else {
                last_result->v.i = (jint)(*env)->CallByteMethodA(env, receiver, mid, jargs);
            }
            last_result->kind = VMP_LAST_INT;
            break;
        case 'C':
            if (is_static) {
                last_result->v.i = (jint)(*env)->CallStaticCharMethodA(env, cls, mid, jargs);
            } else if (use_nonvirtual) {
                last_result->v.i = (jint)(*env)->CallNonvirtualCharMethodA(env, receiver, cls, mid, jargs);
            } else {
                last_result->v.i = (jint)(*env)->CallCharMethodA(env, receiver, mid, jargs);
            }
            last_result->kind = VMP_LAST_INT;
            break;
        case 'S':
            if (is_static) {
                last_result->v.i = (jint)(*env)->CallStaticShortMethodA(env, cls, mid, jargs);
            } else if (use_nonvirtual) {
                last_result->v.i = (jint)(*env)->CallNonvirtualShortMethodA(env, receiver, cls, mid, jargs);
            } else {
                last_result->v.i = (jint)(*env)->CallShortMethodA(env, receiver, mid, jargs);
            }
            last_result->kind = VMP_LAST_INT;
            break;
        case 'I':
            if (is_static) {
                last_result->v.i = (*env)->CallStaticIntMethodA(env, cls, mid, jargs);
            } else if (use_nonvirtual) {
                last_result->v.i = (*env)->CallNonvirtualIntMethodA(env, receiver, cls, mid, jargs);
            } else {
                last_result->v.i = (*env)->CallIntMethodA(env, receiver, mid, jargs);
            }
            last_result->kind = VMP_LAST_INT;
            break;
        default:
            /* Fallback for unexpected return types. */
            if (is_static) {
                last_result->v.i = (*env)->CallStaticIntMethodA(env, cls, mid, jargs);
            } else if (use_nonvirtual) {
                last_result->v.i = (*env)->CallNonvirtualIntMethodA(env, receiver, cls, mid, jargs);
            } else {
                last_result->v.i = (*env)->CallIntMethodA(env, receiver, mid, jargs);
            }
            last_result->kind = VMP_LAST_INT;
            break;
    }

    if ((*env)->ExceptionCheck(env)) goto done;
    rc = 0;

done:
    if (cls) (*env)->DeleteLocalRef(env, cls);
    free(jargs);
    free(class_desc);
    free(name);
    free(sig);
    return rc;
}

/* --------------------------------------------------------------------- */
/* Field / array helpers                                                 */
/* --------------------------------------------------------------------- */

enum {
    VMP_KIND_INT = 0,
    VMP_KIND_WIDE,
    VMP_KIND_OBJECT,
    VMP_KIND_BOOLEAN,
    VMP_KIND_BYTE,
    VMP_KIND_CHAR,
    VMP_KIND_SHORT
};

static int vmp_kind_from_aget_op(int op) {
    return op - VMP_AGET;
}

static int vmp_kind_from_aput_op(int op) {
    return op - VMP_APUT;
}

static int vmp_kind_from_iget_op(int op) {
    return op - VMP_IGET;
}

static int vmp_kind_from_iput_op(int op) {
    return op - VMP_IPUT;
}

static int vmp_kind_from_sget_op(int op) {
    return op - VMP_SGET;
}

static int vmp_kind_from_sput_op(int op) {
    return op - VMP_SPUT;
}

static void vmp_array_get(JNIEnv *env, int kind, vmp_reg_t regs[VMP_MAX_REGS], uint8_t dst, uint8_t arr_r, uint8_t idx_r) {
    if (arr_r >= VMP_MAX_REGS || idx_r >= VMP_MAX_REGS || dst >= VMP_MAX_REGS) return;
    jobject arr = regs[arr_r].l;
    jint idx = regs[idx_r].i;
    if (!arr) {
        vmp_throw_npe(env, "aget on null array");
        return;
    }
    switch (kind) {
        case VMP_KIND_INT: {
            jint v = 0;
            (*env)->GetIntArrayRegion(env, (jintArray) arr, idx, 1, &v);
            VMP_RSET_I(regs[dst], v);
            break;
        }
        case VMP_KIND_WIDE: {
            jlong v = 0;
            (*env)->GetLongArrayRegion(env, (jlongArray) arr, idx, 1, &v);
            regs[dst].j = v;
            break;
        }
        case VMP_KIND_OBJECT:
            regs[dst].l = (*env)->GetObjectArrayElement(env, (jobjectArray) arr, idx);
            break;
        case VMP_KIND_BOOLEAN: {
            jboolean v = JNI_FALSE;
            (*env)->GetBooleanArrayRegion(env, (jbooleanArray) arr, idx, 1, &v);
            VMP_RSET_I(regs[dst], v ? 1 : 0);
            break;
        }
        case VMP_KIND_BYTE: {
            jbyte v = 0;
            (*env)->GetByteArrayRegion(env, (jbyteArray) arr, idx, 1, &v);
            VMP_RSET_I(regs[dst], v);
            break;
        }
        case VMP_KIND_CHAR: {
            jchar v = 0;
            (*env)->GetCharArrayRegion(env, (jcharArray) arr, idx, 1, &v);
            VMP_RSET_I(regs[dst], v);
            break;
        }
        case VMP_KIND_SHORT: {
            jshort v = 0;
            (*env)->GetShortArrayRegion(env, (jshortArray) arr, idx, 1, &v);
            VMP_RSET_I(regs[dst], v);
            break;
        }
        default:
            break;
    }
}

static void vmp_array_put(JNIEnv *env, int kind, vmp_reg_t regs[VMP_MAX_REGS], uint8_t val_r, uint8_t arr_r, uint8_t idx_r) {
    if (arr_r >= VMP_MAX_REGS || idx_r >= VMP_MAX_REGS || val_r >= VMP_MAX_REGS) return;
    jobject arr = regs[arr_r].l;
    jint idx = regs[idx_r].i;
    if (!arr) {
        vmp_throw_npe(env, "aput on null array");
        return;
    }
    switch (kind) {
        case VMP_KIND_INT: {
            jint v = regs[val_r].i;
            (*env)->SetIntArrayRegion(env, (jintArray) arr, idx, 1, &v);
            break;
        }
        case VMP_KIND_WIDE: {
            jlong v = regs[val_r].j;
            (*env)->SetLongArrayRegion(env, (jlongArray) arr, idx, 1, &v);
            break;
        }
        case VMP_KIND_OBJECT:
            (*env)->SetObjectArrayElement(env, (jobjectArray) arr, idx, regs[val_r].l);
            break;
        case VMP_KIND_BOOLEAN: {
            jboolean v = (jboolean) (regs[val_r].i != 0);
            (*env)->SetBooleanArrayRegion(env, (jbooleanArray) arr, idx, 1, &v);
            break;
        }
        case VMP_KIND_BYTE: {
            jbyte v = (jbyte) regs[val_r].i;
            (*env)->SetByteArrayRegion(env, (jbyteArray) arr, idx, 1, &v);
            break;
        }
        case VMP_KIND_CHAR: {
            jchar v = (jchar) regs[val_r].i;
            (*env)->SetCharArrayRegion(env, (jcharArray) arr, idx, 1, &v);
            break;
        }
        case VMP_KIND_SHORT: {
            jshort v = (jshort) regs[val_r].i;
            (*env)->SetShortArrayRegion(env, (jshortArray) arr, idx, 1, &v);
            break;
        }
        default:
            break;
    }
}

static jobject vmp_new_array(JNIEnv *env, const char *array_desc, jint size) {
    if (!array_desc || array_desc[0] != '[') return NULL;
    switch (array_desc[1]) {
        case 'Z': return (jobject) (*env)->NewBooleanArray(env, size);
        case 'B': return (jobject) (*env)->NewByteArray(env, size);
        case 'C': return (jobject) (*env)->NewCharArray(env, size);
        case 'S': return (jobject) (*env)->NewShortArray(env, size);
        case 'I': return (jobject) (*env)->NewIntArray(env, size);
        case 'J': return (jobject) (*env)->NewLongArray(env, size);
        case 'F': return (jobject) (*env)->NewFloatArray(env, size);
        case 'D': return (jobject) (*env)->NewDoubleArray(env, size);
        case 'L':
        case '[': {
            jclass comp = vmp_resolve_class(env, array_desc + 1); /* component descriptor */
            if (!comp) return NULL;
            jobject arr = (jobject) (*env)->NewObjectArray(env, size, comp, NULL);
            (*env)->DeleteLocalRef(env, comp);
            return arr;
        }
        default:
            return NULL;
    }
}

static int vmp_field_get(
        JNIEnv *env,
        int kind,
        int is_static,
        vmp_reg_t regs[VMP_MAX_REGS],
        uint8_t dst,
        uint8_t obj_reg,
        const char *field_ref) {
    char *class_desc = NULL;
    char *name = NULL;
    char *type_desc = NULL;
    jclass cls = NULL;
    jfieldID fid = NULL;
    jobject obj = NULL;
    int rc = -1;

    /* Fast path: check field ID cache */
    fid = vmp_fid_cache_get(env, field_ref, is_static, &cls);
    if (VMP_LIKELY(fid != NULL)) {
        if (!is_static) {
            if (obj_reg >= VMP_MAX_REGS) goto done;
            obj = regs[obj_reg].l;
            if (VMP_UNLIKELY(!obj)) {
                vmp_throw_npe(env, "iget on null object");
                goto done;
            }
        }
        goto do_get;
    }

    /* Slow path: full resolution */
    if (vmp_parse_field_ref(field_ref, &class_desc, &name, &type_desc) != 0) goto done;
    cls = vmp_resolve_class(env, class_desc);
    if (!cls) goto done;
    if (!is_static) {
        if (obj_reg >= VMP_MAX_REGS) goto done;
        obj = regs[obj_reg].l;
        if (VMP_UNLIKELY(!obj)) {
            vmp_throw_npe(env, "iget on null object");
            goto done;
        }
    }
    fid = is_static
          ? (*env)->GetStaticFieldID(env, cls, name, type_desc)
          : (*env)->GetFieldID(env, cls, name, type_desc);
    if (!fid) goto done;
    vmp_fid_cache_put(env, field_ref, is_static, cls, fid);

do_get:
    switch (kind) {
        case VMP_KIND_INT:
            VMP_RSET_I(regs[dst], is_static ? (*env)->GetStaticIntField(env, cls, fid)
                                            : (*env)->GetIntField(env, obj, fid));
            break;
        case VMP_KIND_WIDE:
            regs[dst].j = is_static ? (*env)->GetStaticLongField(env, cls, fid)
                                    : (*env)->GetLongField(env, obj, fid);
            break;
        case VMP_KIND_OBJECT:
            regs[dst].l = is_static ? (*env)->GetStaticObjectField(env, cls, fid)
                                    : (*env)->GetObjectField(env, obj, fid);
            break;
        case VMP_KIND_BOOLEAN:
            VMP_RSET_I(regs[dst], is_static ? ((*env)->GetStaticBooleanField(env, cls, fid) ? 1 : 0)
                                            : ((*env)->GetBooleanField(env, obj, fid) ? 1 : 0));
            break;
        case VMP_KIND_BYTE:
            VMP_RSET_I(regs[dst], is_static ? (*env)->GetStaticByteField(env, cls, fid)
                                            : (*env)->GetByteField(env, obj, fid));
            break;
        case VMP_KIND_CHAR:
            VMP_RSET_I(regs[dst], is_static ? (*env)->GetStaticCharField(env, cls, fid)
                                            : (*env)->GetCharField(env, obj, fid));
            break;
        case VMP_KIND_SHORT:
            VMP_RSET_I(regs[dst], is_static ? (*env)->GetStaticShortField(env, cls, fid)
                                            : (*env)->GetShortField(env, obj, fid));
            break;
        default:
            goto done;
    }
    rc = 0;

done:
    if (cls) (*env)->DeleteLocalRef(env, cls);
    free(class_desc);
    free(name);
    free(type_desc);
    return rc;
}

static int vmp_field_put(
        JNIEnv *env,
        int kind,
        int is_static,
        vmp_reg_t regs[VMP_MAX_REGS],
        uint8_t src,
        uint8_t obj_reg,
        const char *field_ref) {
    char *class_desc = NULL;
    char *name = NULL;
    char *type_desc = NULL;
    jclass cls = NULL;
    jfieldID fid = NULL;
    jobject obj = NULL;
    int rc = -1;

    /* Fast path: check field ID cache */
    fid = vmp_fid_cache_get(env, field_ref, is_static, &cls);
    if (VMP_LIKELY(fid != NULL)) {
        if (!is_static) {
            if (obj_reg >= VMP_MAX_REGS) goto done;
            obj = regs[obj_reg].l;
            if (VMP_UNLIKELY(!obj)) {
                vmp_throw_npe(env, "iput on null object");
                goto done;
            }
        }
        goto do_put;
    }

    /* Slow path: full resolution */
    if (vmp_parse_field_ref(field_ref, &class_desc, &name, &type_desc) != 0) goto done;
    cls = vmp_resolve_class(env, class_desc);
    if (!cls) goto done;
    if (!is_static) {
        if (obj_reg >= VMP_MAX_REGS) goto done;
        obj = regs[obj_reg].l;
        if (VMP_UNLIKELY(!obj)) {
            vmp_throw_npe(env, "iput on null object");
            goto done;
        }
    }
    fid = is_static
          ? (*env)->GetStaticFieldID(env, cls, name, type_desc)
          : (*env)->GetFieldID(env, cls, name, type_desc);
    if (!fid) goto done;
    vmp_fid_cache_put(env, field_ref, is_static, cls, fid);

do_put:
    switch (kind) {
        case VMP_KIND_INT:
            if (is_static) (*env)->SetStaticIntField(env, cls, fid, (jint) regs[src].i);
            else (*env)->SetIntField(env, obj, fid, (jint) regs[src].i);
            break;
        case VMP_KIND_WIDE:
            if (is_static) (*env)->SetStaticLongField(env, cls, fid, (jlong) regs[src].j);
            else (*env)->SetLongField(env, obj, fid, (jlong) regs[src].j);
            break;
        case VMP_KIND_OBJECT:
            if (is_static) (*env)->SetStaticObjectField(env, cls, fid, regs[src].l);
            else (*env)->SetObjectField(env, obj, fid, regs[src].l);
            break;
        case VMP_KIND_BOOLEAN:
            if (is_static) (*env)->SetStaticBooleanField(env, cls, fid, (jboolean) (regs[src].i != 0));
            else (*env)->SetBooleanField(env, obj, fid, (jboolean) (regs[src].i != 0));
            break;
        case VMP_KIND_BYTE:
            if (is_static) (*env)->SetStaticByteField(env, cls, fid, (jbyte) regs[src].i);
            else (*env)->SetByteField(env, obj, fid, (jbyte) regs[src].i);
            break;
        case VMP_KIND_CHAR:
            if (is_static) (*env)->SetStaticCharField(env, cls, fid, (jchar) regs[src].i);
            else (*env)->SetCharField(env, obj, fid, (jchar) regs[src].i);
            break;
        case VMP_KIND_SHORT:
            if (is_static) (*env)->SetStaticShortField(env, cls, fid, (jshort) regs[src].i);
            else (*env)->SetShortField(env, obj, fid, (jshort) regs[src].i);
            break;
        default:
            goto done;
    }
    rc = 0;

done:
    if (cls) (*env)->DeleteLocalRef(env, cls);
    free(class_desc);
    free(name);
    free(type_desc);
    return rc;
}

/* --------------------------------------------------------------------- */
/* Public: load / free                                                   */
/* --------------------------------------------------------------------- */

void enko_vmp_free(void) {
    vmp_cls_cache_clear(NULL);
    vmp_fid_cache_clear(NULL);
    vmp_mid_cache_clear(NULL);
    if (g_vmp.strings) {
        for (uint32_t i = 0; i < g_vmp.string_count; ++i) {
            free(g_vmp.strings[i]);
        }
        free(g_vmp.strings);
    }
    free(g_vmp.methods);
    free(g_vmp.bytecode);
    if (g_vmp.method_tries) {
        for (uint32_t i = 0; i < g_vmp.method_count; ++i) {
            vmp_method_tries_t *mt = &g_vmp.method_tries[i];
            if (mt->tries) {
                for (uint16_t t = 0; t < mt->try_count; ++t) {
                    free(mt->tries[t].handlers);
                }
                free(mt->tries);
            }
        }
        free(g_vmp.method_tries);
        g_vmp.method_tries = NULL;
    }
    memset(&g_vmp, 0, sizeof(g_vmp));
}

int enko_vmp_load(const uint8_t *blob, size_t blob_len) {
    if (!blob || blob_len < 12 + 4 + 256 + 4 + 4) return -1;

    enko_vmp_free();

    /* Decrypt VMP magic on first call. */
    if (kVmpMagic[0] == 0) {
        obs_vmp_magic_dec((char *)kVmpMagic, 11);
        kVmpMagic[11] = '\0';
    }

    blob_reader_t r;
    r.buf = blob;
    r.len = blob_len;
    r.off = 0;

    uint8_t magic[12];
    if (rd_bytes(&r, magic, sizeof(magic)) != 0) goto fail;
    if (memcmp(magic, kVmpMagic, sizeof(kVmpMagic)) != 0) {
        LOGE("VMP blob magic mismatch");
        goto fail;
    }

    uint32_t version = 0;
    if (rd_u32(&r, &version) != 0) goto fail;
    if (version != kVmpVersion && version != kVmpVersionV5) {
        LOGE("VMP blob version mismatch: got=%u expected=%u or %u",
             version, kVmpVersion, kVmpVersionV5);
        goto fail;
    }
    g_vmp.blob_version = version;

    uint32_t string_salt = 0;

    if (version == kVmpVersionV5) {
        /* v5 extended header: header_size, format_flags, width_seed,
         * layout_seed, string_pool_salt, reserved. */
        uint32_t extra_size = 0;
        if (rd_u32(&r, &extra_size) != 0) goto fail;
        if (extra_size < 24 || extra_size > 4096) goto fail;
        if (rd_u32(&r, &g_vmp.v5_format_flags) != 0) goto fail;
        if (rd_u32(&r, &g_vmp.v5_width_table_seed) != 0) goto fail;
        if (rd_u32(&r, &g_vmp.v5_operand_layout_seed) != 0) goto fail;
        if (rd_u32(&r, &string_salt) != 0) goto fail;
        uint32_t reserved = 0;
        if (rd_u32(&r, &reserved) != 0) goto fail;
        /* Skip any forward-compat bytes past the 24 we just read. */
        if (extra_size > 24) {
            if (r.off + (extra_size - 24) > r.len) goto fail;
            r.off += extra_size - 24;
        }
        /* Derive runtime tables from seeds. */
        vmp_v5_derive_width_table(g_vmp.v5_width_table, g_vmp.v5_width_table_seed);
        vmp_v5_derive_layouts(g_vmp.v5_layouts, g_vmp.v5_operand_layout_seed);
    }

    if (rd_bytes(&r, g_vmp.opcode_table, 256) != 0) goto fail;

    if (version == kVmpVersion) {
        if (rd_u32(&r, &string_salt) != 0) goto fail;
    }
    if (rd_u32(&r, &g_vmp.string_count) != 0) goto fail;
    if (g_vmp.string_count > 1000000U) goto fail;
    if (g_vmp.string_count > 0) {
        g_vmp.strings = (char **) calloc(g_vmp.string_count, sizeof(char *));
        if (!g_vmp.strings) goto fail;
    }
    for (uint32_t i = 0; i < g_vmp.string_count; ++i) {
        uint16_t n = 0;
        if (rd_u16(&r, &n) != 0) goto fail;
        if (r.off + n > r.len) goto fail;
        g_vmp.strings[i] = (char *) malloc((size_t) n + 1);
        if (!g_vmp.strings[i]) goto fail;
        memcpy(g_vmp.strings[i], r.buf + r.off, n);
        vmp_crypt_string((uint8_t *)g_vmp.strings[i], n, string_salt, i);
        g_vmp.strings[i][n] = '\0';
        r.off += n;
    }

    if (rd_u32(&r, &g_vmp.method_count) != 0) goto fail;
    if (g_vmp.method_count > 100000U) goto fail;
    if (g_vmp.method_count > 0) {
        g_vmp.methods = (vmp_method_t *) calloc(g_vmp.method_count, sizeof(vmp_method_t));
        if (!g_vmp.methods) goto fail;
    }
    for (uint32_t i = 0; i < g_vmp.method_count; ++i) {
        vmp_method_t *m = &g_vmp.methods[i];
        if (rd_u32(&r, &m->method_id) != 0) goto fail;
        if (rd_u32(&r, &m->class_name_idx) != 0) goto fail;
        if (rd_u32(&r, &m->method_name_idx) != 0) goto fail;
        if (rd_u32(&r, &m->method_sig_idx) != 0) goto fail;
        if (rd_u16(&r, &m->registers_size) != 0) goto fail;
        if (rd_u16(&r, &m->ins_size) != 0) goto fail;
        if (rd_u16(&r, &m->outs_size) != 0) goto fail;
        if (rd_u16(&r, &m->tries_count) != 0) goto fail;
        if (rd_i32(&r, &m->op_obfs_seed) != 0) goto fail;
        if (rd_i32(&r, &m->bytecode_off) != 0) goto fail;
        if (rd_i32(&r, &m->bytecode_size) != 0) goto fail;
    }

    if (rd_u32(&r, &g_vmp.bytecode_size) != 0) goto fail;
    if (g_vmp.bytecode_size > 0) {
        if (r.off + g_vmp.bytecode_size > r.len) goto fail;
        g_vmp.bytecode = (uint8_t *) malloc(g_vmp.bytecode_size);
        if (!g_vmp.bytecode) goto fail;
        memcpy(g_vmp.bytecode, r.buf + r.off, g_vmp.bytecode_size);
        r.off += g_vmp.bytecode_size;
    }

    /* Parse try-catch section into method_tries tables. */
    if (g_vmp.method_count > 0) {
        g_vmp.method_tries = (vmp_method_tries_t *) calloc(g_vmp.method_count, sizeof(vmp_method_tries_t));
        if (!g_vmp.method_tries) goto fail;
    }
    for (uint32_t i = 0; i < g_vmp.method_count; ++i) {
        vmp_method_tries_t *mt = &g_vmp.method_tries[i];
        if (rd_u16(&r, &mt->try_count) != 0) goto fail;
        if (mt->try_count > 0) {
            mt->tries = (vmp_try_block_t *) calloc(mt->try_count, sizeof(vmp_try_block_t));
            if (!mt->tries) goto fail;
        }
        for (uint16_t t = 0; t < mt->try_count; ++t) {
            vmp_try_block_t *tb = &mt->tries[t];
            if (rd_u16(&r, &tb->start_pc) != 0) goto fail;
            if (rd_u16(&r, &tb->end_pc) != 0) goto fail;
            if (rd_u16(&r, &tb->handler_count) != 0) goto fail;
            if (tb->handler_count > 0) {
                tb->handlers = (vmp_catch_handler_t *) calloc(tb->handler_count, sizeof(vmp_catch_handler_t));
                if (!tb->handlers) goto fail;
            }
            for (uint16_t h = 0; h < tb->handler_count; ++h) {
                if (rd_i32(&r, &tb->handlers[h].type_str_idx) != 0) goto fail;
                if (rd_i32(&r, &tb->handlers[h].handler_pc) != 0) goto fail;
            }
            if (rd_i32(&r, &tb->catch_all_pc) != 0) goto fail;
        }
    }

    g_vmp.loaded = 1;
    g_vmp.core_tier = VMP_TIER_LIGHT;
    LOGI("VMP blob loaded: strings=%u methods=%u bytecode=%u tier=%s",
         g_vmp.string_count, g_vmp.method_count, g_vmp.bytecode_size,
         vmp_tier_name(g_vmp.core_tier));
    return 0;

fail:
    LOGE("VMP blob parse failed at offset=%zu", r.off);
    enko_vmp_free();
    return -1;
}

int enko_vmp_set_tier(int tier) {
    g_vmp.core_tier = vmp_clamp_tier(tier);
    LOGI("VMP core tier selected: %s", vmp_tier_name(g_vmp.core_tier));
    return 0;
}

/* --------------------------------------------------------------------- */
/* Interpreter                                                           */
/* --------------------------------------------------------------------- */

static void vmp_load_entry_args(
        JNIEnv *env,
        const vmp_method_t *method,
        jobject thiz,
        jobjectArray args,
        vmp_reg_t regs[VMP_MAX_REGS]) {
    if (!method) return;
    vmp_zero_regs(regs, VMP_MAX_REGS);

    const char *sig = vmp_method_sig(method);
    if (!sig) return;

    int start = 0;
    if (method->registers_size >= method->ins_size) {
        start = (int) method->registers_size - (int) method->ins_size;
    }
    if (start < 0) start = 0;
    if (start >= VMP_MAX_REGS) return;

    int reg_pos = start;
    if (thiz != NULL && reg_pos < VMP_MAX_REGS) {
        regs[reg_pos++].l = thiz;
    }

    const char *lp = strchr(sig, '(');
    const char *rp = strchr(sig, ')');
    if (!lp || !rp || rp < lp) return;

    jsize arg_count = args ? (*env)->GetArrayLength(env, args) : 0;
    int arg_index = 0;
    const char *p = lp + 1;
    while (p < rp && *p && reg_pos < VMP_MAX_REGS) {
        const char *e = vmp_desc_end(p);
        if (!e || e <= p || e > rp) break;

        jobject arg_obj = NULL;
        if (args && arg_index < arg_count) {
            arg_obj = (*env)->GetObjectArrayElement(env, args, arg_index);
        }

        vmp_reg_t v;
        memset(&v, 0, sizeof(v));
        if (vmp_unbox_to_reg(env, arg_obj, p, &v) == 0) {
            regs[reg_pos] = v;
            if (vmp_desc_width_words(p) == 2 && reg_pos + 1 < VMP_MAX_REGS) {
                regs[reg_pos + 1] = v;
            }
        }

        if (arg_obj && !vmp_desc_is_ref(p)) {
            (*env)->DeleteLocalRef(env, arg_obj);
        }

        reg_pos += vmp_desc_width_words(p);
        arg_index++;
        p = e;
    }
}

static int vmp_binop_is_2addr(const vmp_insn_t *in) {
    return in->src2 == 0 && in->imm == 0;
}

static int32_t vmp_bin_lhs_i(const vmp_insn_t *in, vmp_reg_t regs[VMP_MAX_REGS]) {
    return vmp_binop_is_2addr(in) ? regs[in->dst].i : regs[in->src1].i;
}

static int64_t vmp_bin_lhs_j(const vmp_insn_t *in, vmp_reg_t regs[VMP_MAX_REGS]) {
    return vmp_binop_is_2addr(in) ? regs[in->dst].j : regs[in->src1].j;
}

static jfloat vmp_bin_lhs_f(const vmp_insn_t *in, vmp_reg_t regs[VMP_MAX_REGS]) {
    return vmp_binop_is_2addr(in) ? regs[in->dst].f : regs[in->src1].f;
}

static jdouble vmp_bin_lhs_d(const vmp_insn_t *in, vmp_reg_t regs[VMP_MAX_REGS]) {
    return vmp_binop_is_2addr(in) ? regs[in->dst].d : regs[in->src1].d;
}

static int32_t vmp_bin_rhs_i(const vmp_insn_t *in, vmp_reg_t regs[VMP_MAX_REGS]) {
    if (in->src2 == 0) {
        if (in->imm == VMP_BINOP_REG0_SENTINEL) return regs[0].i;
        if (in->imm == VMP_BINOP_LIT_ZERO_SENTINEL) return 0;
        if (in->imm == 0) return regs[in->src1].i; /* 2addr */
        return in->imm;                            /* lit */
    }
    return regs[in->src2].i;                       /* normal 23x */
}

static int64_t vmp_bin_rhs_j(const vmp_insn_t *in, vmp_reg_t regs[VMP_MAX_REGS]) {
    if (in->src2 == 0) {
        if (in->imm == VMP_BINOP_REG0_SENTINEL) return regs[0].j;
        if (in->imm == VMP_BINOP_LIT_ZERO_SENTINEL) return 0;
        if (in->imm == 0) return regs[in->src1].j; /* 2addr */
        return (int64_t) in->imm;                  /* lit fallback */
    }
    return regs[in->src2].j;                       /* normal */
}

static jfloat vmp_bin_rhs_f(const vmp_insn_t *in, vmp_reg_t regs[VMP_MAX_REGS]) {
    return vmp_binop_is_2addr(in) ? regs[in->src1].f : regs[in->src2].f;
}

static jdouble vmp_bin_rhs_d(const vmp_insn_t *in, vmp_reg_t regs[VMP_MAX_REGS]) {
    return vmp_binop_is_2addr(in) ? regs[in->src1].d : regs[in->src2].d;
}

static int vmp_branch_cond_eq(vmp_reg_t a, vmp_reg_t b) {
    return a.j == b.j;
}

static int vmp_branch_cond_ne(vmp_reg_t a, vmp_reg_t b) {
    return a.j != b.j;
}

static int vmp_i64_to_int_checked(int64_t v, int *out) {
    if (!out) return -1;
    if (v < INT_MIN || v > INT_MAX) return -1;
    *out = (int) v;
    return 0;
}

static int vmp_parse_i64_token(const char **pp, int64_t *out) {
    if (!pp || !*pp || !out) return -1;
    char *end = NULL;
    long long v = strtoll(*pp, &end, 10);
    if (end == *pp) return -1;
    *out = (int64_t) v;
    *pp = end;
    return 0;
}

/*
 * switch payload spec encoding (from compiler):
 *   packed : "PS|<first_key>|<rel0>,<rel1>,..."
 *   sparse : "SS|<key0>:<rel0>,<key1>:<rel1>,..."
 * return:
 *   1  => matched, out_rel filled
 *   0  => no match (fallthrough)
 *  -1  => malformed payload
 */
static int vmp_eval_switch_spec(const char *spec, int32_t key, int *out_rel) {
    if (!spec || !out_rel) return -1;

    if (strncmp(spec, "PS|", 3) == 0) {
        const char *p = spec + 3;
        int64_t first_key = 0;
        if (vmp_parse_i64_token(&p, &first_key) != 0) return -1;
        if (*p != '|') return -1;
        p++;

        int64_t wanted = (int64_t) key - first_key;
        if (wanted < 0) return 0;
        if (*p == '\0') return 0;

        int64_t idx = 0;
        while (*p) {
            int64_t rel = 0;
            if (vmp_parse_i64_token(&p, &rel) != 0) return -1;
            if (idx == wanted) {
                return (vmp_i64_to_int_checked(rel, out_rel) == 0) ? 1 : -1;
            }
            idx++;
            if (*p == ',') {
                p++;
                continue;
            }
            if (*p == '\0') break;
            return -1;
        }
        return 0;
    }

    if (strncmp(spec, "SS|", 3) == 0) {
        const char *p = spec + 3;
        if (*p == '\0') return 0;
        while (*p) {
            int64_t k = 0, rel = 0;
            if (vmp_parse_i64_token(&p, &k) != 0) return -1;
            if (*p != ':') return -1;
            p++;
            if (vmp_parse_i64_token(&p, &rel) != 0) return -1;
            if (k == (int64_t) key) {
                return (vmp_i64_to_int_checked(rel, out_rel) == 0) ? 1 : -1;
            }
            if (*p == ',') {
                p++;
                continue;
            }
            if (*p == '\0') break;
            return -1;
        }
        return 0;
    }

    return -1;
}

static int vmp_hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static int vmp_hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    if (!hex) return -1;
    if (out_len == 0) return (*hex == '\0') ? 0 : -1;
    if (!out) return -1;

    for (size_t i = 0; i < out_len; ++i) {
        int hi = vmp_hex_nibble(hex[i * 2]);
        int lo = vmp_hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t) ((hi << 4) | lo);
    }
    return (hex[out_len * 2] == '\0') ? 0 : -1;
}

static uint16_t vmp_read_le16(const uint8_t *p) {
    return (uint16_t) p[0] | ((uint16_t) p[1] << 8);
}

static uint32_t vmp_read_le32(const uint8_t *p) {
    return (uint32_t) p[0] |
           ((uint32_t) p[1] << 8) |
           ((uint32_t) p[2] << 16) |
           ((uint32_t) p[3] << 24);
}

static uint64_t vmp_read_le64(const uint8_t *p) {
    uint64_t lo = vmp_read_le32(p);
    uint64_t hi = vmp_read_le32(p + 4);
    return lo | (hi << 32);
}

static int vmp_is_array_of(JNIEnv *env, jobject arr, const char *desc) {
    if (!env || !arr || !desc) return 0;
    jclass cls = (*env)->FindClass(env, desc);
    if (!cls) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        return 0;
    }
    int ok = (*env)->IsInstanceOf(env, arr, cls);
    (*env)->DeleteLocalRef(env, cls);
    return ok;
}

/*
 * fill-array-data payload spec encoding (from compiler):
 *   "FA|<elem_width>|<elem_count>|<hex_bytes>"
 */
static int vmp_apply_fill_array_spec(JNIEnv *env, jobject arr, const char *spec) {
    if (!env || !arr || !spec) return -1;
    if (strncmp(spec, "FA|", 3) != 0) return -1;

    const char *p = spec + 3;
    int64_t elem_width64 = 0, elem_count64 = 0;
    if (vmp_parse_i64_token(&p, &elem_width64) != 0) return -1;
    if (*p != '|') return -1;
    p++;
    if (vmp_parse_i64_token(&p, &elem_count64) != 0) return -1;
    if (*p != '|') return -1;
    p++;

    if (elem_width64 <= 0 || elem_count64 < 0) return -1;
    if (elem_width64 != 1 && elem_width64 != 2 && elem_width64 != 4 && elem_width64 != 8) return -1;
    if (elem_count64 > INT_MAX) return -1;

    size_t elem_width = (size_t) elem_width64;
    size_t elem_count = (size_t) elem_count64;
    if (elem_count > SIZE_MAX / elem_width) return -1;
    size_t total_bytes = elem_count * elem_width;
    if (strlen(p) != total_bytes * 2) return -1;

    jsize arr_len = (*env)->GetArrayLength(env, (jarray) arr);
    if ((*env)->ExceptionCheck(env)) return -1;
    if ((size_t) arr_len < elem_count) return -1;
    if (elem_count == 0) return 0;

    uint8_t *raw = (uint8_t *) malloc(total_bytes);
    if (!raw) return -1;
    if (vmp_hex_to_bytes(p, raw, total_bytes) != 0) {
        free(raw);
        return -1;
    }

    int rc = -1;

    if (vmp_is_array_of(env, arr, "[B")) {
        if (elem_width != 1) goto done;
        (*env)->SetByteArrayRegion(env, (jbyteArray) arr, 0, (jsize) elem_count, (const jbyte *) raw);
        rc = (*env)->ExceptionCheck(env) ? -1 : 0;
        goto done;
    }

    if (vmp_is_array_of(env, arr, "[Z")) {
        if (elem_width != 1) goto done;
        jboolean *vals = (jboolean *) calloc(elem_count, sizeof(jboolean));
        if (!vals) goto done;
        for (size_t i = 0; i < elem_count; ++i) vals[i] = raw[i] ? JNI_TRUE : JNI_FALSE;
        (*env)->SetBooleanArrayRegion(env, (jbooleanArray) arr, 0, (jsize) elem_count, vals);
        free(vals);
        rc = (*env)->ExceptionCheck(env) ? -1 : 0;
        goto done;
    }

    if (vmp_is_array_of(env, arr, "[S")) {
        if (elem_width != 2) goto done;
        jshort *vals = (jshort *) calloc(elem_count, sizeof(jshort));
        if (!vals) goto done;
        for (size_t i = 0; i < elem_count; ++i) vals[i] = (jshort) vmp_read_le16(raw + i * 2);
        (*env)->SetShortArrayRegion(env, (jshortArray) arr, 0, (jsize) elem_count, vals);
        free(vals);
        rc = (*env)->ExceptionCheck(env) ? -1 : 0;
        goto done;
    }

    if (vmp_is_array_of(env, arr, "[C")) {
        if (elem_width != 2) goto done;
        jchar *vals = (jchar *) calloc(elem_count, sizeof(jchar));
        if (!vals) goto done;
        for (size_t i = 0; i < elem_count; ++i) vals[i] = (jchar) vmp_read_le16(raw + i * 2);
        (*env)->SetCharArrayRegion(env, (jcharArray) arr, 0, (jsize) elem_count, vals);
        free(vals);
        rc = (*env)->ExceptionCheck(env) ? -1 : 0;
        goto done;
    }

    if (vmp_is_array_of(env, arr, "[I")) {
        if (elem_width != 4) goto done;
        jint *vals = (jint *) calloc(elem_count, sizeof(jint));
        if (!vals) goto done;
        for (size_t i = 0; i < elem_count; ++i) vals[i] = (jint) vmp_read_le32(raw + i * 4);
        (*env)->SetIntArrayRegion(env, (jintArray) arr, 0, (jsize) elem_count, vals);
        free(vals);
        rc = (*env)->ExceptionCheck(env) ? -1 : 0;
        goto done;
    }

    if (vmp_is_array_of(env, arr, "[F")) {
        if (elem_width != 4) goto done;
        jfloat *vals = (jfloat *) calloc(elem_count, sizeof(jfloat));
        if (!vals) goto done;
        for (size_t i = 0; i < elem_count; ++i) {
            uint32_t bits = vmp_read_le32(raw + i * 4);
            float f = 0.0f;
            memcpy(&f, &bits, sizeof(f));
            vals[i] = (jfloat) f;
        }
        (*env)->SetFloatArrayRegion(env, (jfloatArray) arr, 0, (jsize) elem_count, vals);
        free(vals);
        rc = (*env)->ExceptionCheck(env) ? -1 : 0;
        goto done;
    }

    if (vmp_is_array_of(env, arr, "[J")) {
        if (elem_width != 8) goto done;
        jlong *vals = (jlong *) calloc(elem_count, sizeof(jlong));
        if (!vals) goto done;
        for (size_t i = 0; i < elem_count; ++i) vals[i] = (jlong) vmp_read_le64(raw + i * 8);
        (*env)->SetLongArrayRegion(env, (jlongArray) arr, 0, (jsize) elem_count, vals);
        free(vals);
        rc = (*env)->ExceptionCheck(env) ? -1 : 0;
        goto done;
    }

    if (vmp_is_array_of(env, arr, "[D")) {
        if (elem_width != 8) goto done;
        jdouble *vals = (jdouble *) calloc(elem_count, sizeof(jdouble));
        if (!vals) goto done;
        for (size_t i = 0; i < elem_count; ++i) {
            uint64_t bits = vmp_read_le64(raw + i * 8);
            double d = 0.0;
            memcpy(&d, &bits, sizeof(d));
            vals[i] = (jdouble) d;
        }
        (*env)->SetDoubleArrayRegion(env, (jdoubleArray) arr, 0, (jsize) elem_count, vals);
        free(vals);
        rc = (*env)->ExceptionCheck(env) ? -1 : 0;
        goto done;
    }

done:
    free(raw);
    return rc;
}

__attribute__((annotate("sub")))
/* ── v5 dispatch (session 2: 15 simple opcodes) ─────────────────────────
 *
 * Independent code path from the v4 dispatcher above. Walks the
 * bytecode stream as a byte-offset PC, reads opcode at byte 0 (anchored
 * per format spec), looks up width and operand layout from per-build
 * tables derived at load time.
 *
 * This session implements a *minimal viable* opcode set so smoke
 * methods (NOP, simple moves, basic arithmetic, branches, returns) can
 * run end-to-end. Sessions 3 and 4 port the remaining ~140 handlers
 * and add full parity testing.
 *
 * Any opcode not implemented here returns NULL with a runtime
 * exception, so a misconfigured production deploy fails loudly rather
 * than silently producing wrong values.
 */
static jobject vmp_run_interpreter_v5(JNIEnv *env, const vmp_method_t *method,
                                       vmp_reg_t regs[VMP_MAX_REGS]) {
    if (method->bytecode_off < 0 || method->bytecode_size < 0) {
        vmp_throw_runtime(env, "v5: invalid VMP method bytecode range");
        return NULL;
    }
    if ((uint32_t)method->bytecode_off + (uint32_t)method->bytecode_size > _active_ctx->bytecode_size) {
        vmp_throw_runtime(env, "v5: VMP method bytecode out of range");
        return NULL;
    }

    const uint8_t *bc = _active_ctx->bytecode + method->bytecode_off;
    const uint32_t bc_len = (uint32_t)method->bytecode_size;
    const uint8_t *width_tbl = _active_ctx->v5_width_table;
    const uint8_t *opcode_table = _active_ctx->opcode_table;

    /* PushLocalFrame mirrors v4 — JNI locals from this method
     * accumulate in a frame released on return. */
    if ((*env)->PushLocalFrame(env, 256) < 0) {
        vmp_throw_runtime(env, "v5: PushLocalFrame failed");
        return NULL;
    }

    uint32_t pc = 0;
    int returned = 0;
    int return_op = VMP_RETURN_VOID;
    vmp_reg_t ret_reg;
    memset(&ret_reg, 0, sizeof(ret_reg));

    /* Step budget — bytecode size in bytes × small factor. */
    uint32_t step_budget = bc_len * 64U + 4096U;
    if (step_budget > 1U << 24) step_budget = 1U << 24;

    while (pc < bc_len) {
        if (step_budget-- == 0) {
            vmp_throw_runtime(env, "v5: step budget exhausted");
            (*env)->PopLocalFrame(env, NULL);
            return NULL;
        }

        uint8_t op_byte = bc[pc + 0];  /* opcode anchored at byte 0 */
        int real_op = opcode_table[op_byte];
        if (real_op < 0 || real_op >= VMP_OP_COUNT) {
            vmp_throw_runtime(env, "v5: opcode out of range");
            (*env)->PopLocalFrame(env, NULL);
            return NULL;
        }
        uint8_t width = width_tbl[real_op];
        int layout_idx = vmp_v5_layout_index_for_width(width);
        if (layout_idx < 0 || pc + width > bc_len) {
            vmp_throw_runtime(env, "v5: width overrun");
            (*env)->PopLocalFrame(env, NULL);
            return NULL;
        }
        const vmp_v5_layout_t *L = &_active_ctx->v5_layouts[layout_idx];

        /* Pre-extract common operand bytes; not all opcodes use them. */
        uint8_t dst   = (width >= VMP_V5_W4)  ? bc[pc + L->dst_pos]  : 0;
        uint8_t src1  = (width == VMP_V5_W4 || width == VMP_V5_W8) ? bc[pc + L->src1_pos] : 0;
        uint8_t src2  = (width == VMP_V5_W8)  ? bc[pc + L->src2_pos] : 0;
        int32_t imm32 = 0;
        if (width == VMP_V5_W8) {
            memcpy(&imm32, bc + pc + L->multi_start, 4);
        }
        int64_t imm64 = 0;
        if (width == VMP_V5_W12) {
            memcpy(&imm64, bc + pc + L->multi_start, 8);
        }

        uint32_t next_pc = pc + width;

        switch (real_op) {
            case VMP_NOP:
                break;

            case VMP_MOVE:
            case VMP_MOVE_WIDE:
            case VMP_MOVE_OBJECT:
                regs[dst] = regs[src1];
                break;

            case VMP_MOVE_RESULT:
            case VMP_MOVE_RESULT_WIDE:
            case VMP_MOVE_RESULT_OBJECT:
                /* Session-2 simplification: we don't yet have a
                 * v5-side last_result staging (invokes aren't
                 * implemented), so move_result is a no-op. */
                break;

            case VMP_MOVE_EXCEPTION:
                /* No exception handling in session 2. */
                regs[dst].l = NULL;
                break;

            case VMP_RETURN_VOID:
                returned = 1;
                return_op = VMP_RETURN_VOID;
                break;

            case VMP_RETURN:
                returned = 1;
                return_op = VMP_RETURN;
                ret_reg = regs[dst];  /* dst doubles as the return-source reg */
                break;

            case VMP_RETURN_WIDE:
                returned = 1;
                return_op = VMP_RETURN_WIDE;
                ret_reg = regs[dst];
                break;

            case VMP_RETURN_OBJECT:
                returned = 1;
                return_op = VMP_RETURN_OBJECT;
                ret_reg = regs[dst];
                break;

            case VMP_NEG_INT:
                regs[dst].i = -regs[src1].i;
                break;

            case VMP_INT_TO_LONG:
                regs[dst].j = (int64_t)regs[src1].i;
                break;

            case VMP_ADD_INT:
                regs[dst].i = regs[src1].i + regs[src2].i;
                break;

            case VMP_SUB_INT:
                regs[dst].i = regs[src1].i - regs[src2].i;
                break;

            case VMP_GOTO:
                /* W8: imm32 is the byte-offset branch target relative to current PC. */
                next_pc = (uint32_t)((int32_t)pc + imm32);
                if (next_pc >= bc_len) {
                    vmp_throw_runtime(env, "v5: goto out of bounds");
                    (*env)->PopLocalFrame(env, NULL);
                    return NULL;
                }
                break;

            case VMP_IF_EQZ:
                if (regs[dst].j == 0) {
                    next_pc = (uint32_t)((int32_t)pc + imm32);
                    if (next_pc >= bc_len) {
                        vmp_throw_runtime(env, "v5: if_eqz target out of bounds");
                        (*env)->PopLocalFrame(env, NULL);
                        return NULL;
                    }
                }
                break;

            case VMP_IF_EQ:
                /* W8: dst = lhs reg, src1 = rhs reg, imm32 = branch byte-offset. */
                if (regs[dst].i == regs[src1].i) {
                    next_pc = (uint32_t)((int32_t)pc + imm32);
                    if (next_pc >= bc_len) {
                        vmp_throw_runtime(env, "v5: if_eq target out of bounds");
                        (*env)->PopLocalFrame(env, NULL);
                        return NULL;
                    }
                }
                break;

            case VMP_MONITOR_ENTER:
                if (regs[dst].l) {
                    (*env)->MonitorEnter(env, regs[dst].l);
                }
                break;

            case VMP_MONITOR_EXIT:
                if (regs[dst].l) {
                    (*env)->MonitorExit(env, regs[dst].l);
                }
                break;

            case VMP_ARRAY_LENGTH:
                if (regs[src1].l == NULL) {
                    vmp_throw_runtime(env, "v5: array-length on NULL");
                    (*env)->PopLocalFrame(env, NULL);
                    return NULL;
                }
                regs[dst].i = (int32_t)(*env)->GetArrayLength(env, (jarray)regs[src1].l);
                break;

            /* ── Const family ───────────────────────────────────── */
            case VMP_CONST:
                regs[dst].i = imm32;
                break;

            case VMP_CONST_WIDE: {
                /* W12: imm64 sits in the multi-byte payload (already
                 * read into imm64 above). v4 paired CONST + CONST_WIDE_HI32
                 * to carry 64-bit consts; v5 packs the full i64 inline. */
                regs[dst].j = imm64;
                if (dst + 1 < VMP_MAX_REGS) regs[dst + 1] = regs[dst];
                break;
            }

            case VMP_CONST_STRING: {
                const char *s = vmp_pool_get((uint32_t)imm32);
                regs[dst].l = s ? (*env)->NewStringUTF(env, s) : NULL;
                break;
            }

            case VMP_CONST_CLASS: {
                const char *desc = vmp_pool_get((uint32_t)imm32);
                regs[dst].l = desc ? vmp_resolve_class(env, desc) : NULL;
                if ((*env)->ExceptionCheck(env)) {
                    (*env)->PopLocalFrame(env, NULL);
                    return NULL;
                }
                break;
            }

            /* ── Throw ──────────────────────────────────────────── */
            case VMP_THROW: {
                if (regs[dst].l) {
                    (*env)->Throw(env, (jthrowable)regs[dst].l);
                }
                /* Exception handling for v5 is bound to byte-PC try blocks
                 * (session 3.5). Until then, surface the throw to the
                 * caller via JNI exception state. */
                (*env)->PopLocalFrame(env, NULL);
                return NULL;
            }

            /* ── Branches: rest of if-test family (W8, imm32 = byte offset) ── */
            case VMP_IF_NE:
                if (regs[dst].i != regs[src1].i) next_pc = (uint32_t)((int32_t)pc + imm32);
                break;
            case VMP_IF_LT:
                if (regs[dst].i < regs[src1].i) next_pc = (uint32_t)((int32_t)pc + imm32);
                break;
            case VMP_IF_GE:
                if (regs[dst].i >= regs[src1].i) next_pc = (uint32_t)((int32_t)pc + imm32);
                break;
            case VMP_IF_GT:
                if (regs[dst].i > regs[src1].i) next_pc = (uint32_t)((int32_t)pc + imm32);
                break;
            case VMP_IF_LE:
                if (regs[dst].i <= regs[src1].i) next_pc = (uint32_t)((int32_t)pc + imm32);
                break;

            /* ── If-testz family ────────────────────────────────── */
            case VMP_IF_NEZ:
                if (regs[dst].j != 0) next_pc = (uint32_t)((int32_t)pc + imm32);
                break;
            case VMP_IF_LTZ:
                if (regs[dst].i < 0) next_pc = (uint32_t)((int32_t)pc + imm32);
                break;
            case VMP_IF_GEZ:
                if (regs[dst].i >= 0) next_pc = (uint32_t)((int32_t)pc + imm32);
                break;
            case VMP_IF_GTZ:
                if (regs[dst].i > 0) next_pc = (uint32_t)((int32_t)pc + imm32);
                break;
            case VMP_IF_LEZ:
                if (regs[dst].i <= 0) next_pc = (uint32_t)((int32_t)pc + imm32);
                break;

            /* ── Compare ops ────────────────────────────────────── */
            case VMP_CMP_LONG: {
                int64_t a = regs[src1].j, b = regs[src2].j;
                regs[dst].i = (a < b) ? -1 : (a > b) ? 1 : 0;
                break;
            }
            case VMP_CMPL_FLOAT: {
                float a = regs[src1].f, b = regs[src2].f;
                regs[dst].i = (a > b) ? 1 : (a == b) ? 0 : -1;  /* NaN → -1 */
                break;
            }
            case VMP_CMPG_FLOAT: {
                float a = regs[src1].f, b = regs[src2].f;
                regs[dst].i = (a < b) ? -1 : (a == b) ? 0 : 1;  /* NaN → +1 */
                break;
            }
            case VMP_CMPL_DOUBLE: {
                double a = regs[src1].d, b = regs[src2].d;
                regs[dst].i = (a > b) ? 1 : (a == b) ? 0 : -1;
                break;
            }
            case VMP_CMPG_DOUBLE: {
                double a = regs[src1].d, b = regs[src2].d;
                regs[dst].i = (a < b) ? -1 : (a == b) ? 0 : 1;
                break;
            }

            /* ── int binops (extending session 2's ADD/SUB) ─────── */
            case VMP_MUL_INT: regs[dst].i = regs[src1].i * regs[src2].i; break;
            case VMP_DIV_INT:
                if (regs[src2].i == 0) {
                    vmp_throw_arith(env, "/ by zero");
                    (*env)->PopLocalFrame(env, NULL);
                    return NULL;
                }
                regs[dst].i = regs[src1].i / regs[src2].i;
                break;
            case VMP_REM_INT:
                if (regs[src2].i == 0) {
                    vmp_throw_arith(env, "/ by zero");
                    (*env)->PopLocalFrame(env, NULL);
                    return NULL;
                }
                regs[dst].i = regs[src1].i % regs[src2].i;
                break;
            case VMP_AND_INT: regs[dst].i = regs[src1].i & regs[src2].i; break;
            case VMP_OR_INT:  regs[dst].i = regs[src1].i | regs[src2].i; break;
            case VMP_XOR_INT: regs[dst].i = regs[src1].i ^ regs[src2].i; break;
            case VMP_SHL_INT: regs[dst].i = regs[src1].i << (regs[src2].i & 31); break;
            case VMP_SHR_INT: regs[dst].i = regs[src1].i >> (regs[src2].i & 31); break;
            case VMP_USHR_INT:
                regs[dst].i = (int32_t)((uint32_t)regs[src1].i >> (regs[src2].i & 31));
                break;

            /* ── long binops ─────────────────────────────────────── */
            case VMP_ADD_LONG: regs[dst].j = regs[src1].j + regs[src2].j; break;
            case VMP_SUB_LONG: regs[dst].j = regs[src1].j - regs[src2].j; break;
            case VMP_MUL_LONG: regs[dst].j = regs[src1].j * regs[src2].j; break;
            case VMP_DIV_LONG:
                if (regs[src2].j == 0) {
                    vmp_throw_arith(env, "/ by zero");
                    (*env)->PopLocalFrame(env, NULL);
                    return NULL;
                }
                regs[dst].j = regs[src1].j / regs[src2].j;
                break;
            case VMP_REM_LONG:
                if (regs[src2].j == 0) {
                    vmp_throw_arith(env, "/ by zero");
                    (*env)->PopLocalFrame(env, NULL);
                    return NULL;
                }
                regs[dst].j = regs[src1].j % regs[src2].j;
                break;
            case VMP_AND_LONG: regs[dst].j = regs[src1].j & regs[src2].j; break;
            case VMP_OR_LONG:  regs[dst].j = regs[src1].j | regs[src2].j; break;
            case VMP_XOR_LONG: regs[dst].j = regs[src1].j ^ regs[src2].j; break;
            case VMP_SHL_LONG: regs[dst].j = regs[src1].j << (regs[src2].i & 63); break;
            case VMP_SHR_LONG: regs[dst].j = regs[src1].j >> (regs[src2].i & 63); break;
            case VMP_USHR_LONG:
                regs[dst].j = (int64_t)((uint64_t)regs[src1].j >> (regs[src2].i & 63));
                break;

            /* ── float/double binops ────────────────────────────── */
            case VMP_ADD_FLOAT:  regs[dst].f = regs[src1].f + regs[src2].f; break;
            case VMP_SUB_FLOAT:  regs[dst].f = regs[src1].f - regs[src2].f; break;
            case VMP_MUL_FLOAT:  regs[dst].f = regs[src1].f * regs[src2].f; break;
            case VMP_DIV_FLOAT:  regs[dst].f = regs[src1].f / regs[src2].f; break;
            case VMP_REM_FLOAT:  regs[dst].f = (float)fmod(regs[src1].f, regs[src2].f); break;
            case VMP_ADD_DOUBLE: regs[dst].d = regs[src1].d + regs[src2].d; break;
            case VMP_SUB_DOUBLE: regs[dst].d = regs[src1].d - regs[src2].d; break;
            case VMP_MUL_DOUBLE: regs[dst].d = regs[src1].d * regs[src2].d; break;
            case VMP_DIV_DOUBLE: regs[dst].d = regs[src1].d / regs[src2].d; break;
            case VMP_REM_DOUBLE: regs[dst].d = fmod(regs[src1].d, regs[src2].d); break;

            /* ── More unops / conversions ───────────────────────── */
            case VMP_NOT_INT:    regs[dst].i = ~regs[src1].i; break;
            case VMP_NEG_LONG:   regs[dst].j = -regs[src1].j; break;
            case VMP_NOT_LONG:   regs[dst].j = ~regs[src1].j; break;
            case VMP_NEG_FLOAT:  regs[dst].f = -regs[src1].f; break;
            case VMP_NEG_DOUBLE: regs[dst].d = -regs[src1].d; break;
            case VMP_INT_TO_FLOAT:    regs[dst].f = (float)regs[src1].i; break;
            case VMP_INT_TO_DOUBLE:   regs[dst].d = (double)regs[src1].i; break;
            case VMP_LONG_TO_INT:     regs[dst].i = (int32_t)regs[src1].j; break;
            case VMP_LONG_TO_FLOAT:   regs[dst].f = (float)regs[src1].j; break;
            case VMP_LONG_TO_DOUBLE:  regs[dst].d = (double)regs[src1].j; break;
            case VMP_FLOAT_TO_INT:    regs[dst].i = (int32_t)regs[src1].f; break;
            case VMP_FLOAT_TO_LONG:   regs[dst].j = (int64_t)regs[src1].f; break;
            case VMP_FLOAT_TO_DOUBLE: regs[dst].d = (double)regs[src1].f; break;
            case VMP_DOUBLE_TO_INT:   regs[dst].i = (int32_t)regs[src1].d; break;
            case VMP_DOUBLE_TO_LONG:  regs[dst].j = (int64_t)regs[src1].d; break;
            case VMP_DOUBLE_TO_FLOAT: regs[dst].f = (float)regs[src1].d; break;
            case VMP_INT_TO_BYTE:     regs[dst].i = (int8_t)regs[src1].i; break;
            case VMP_INT_TO_CHAR:     regs[dst].i = (uint16_t)regs[src1].i; break;
            case VMP_INT_TO_SHORT:    regs[dst].i = (int16_t)regs[src1].i; break;

            /* ── Type ops ───────────────────────────────────────── */
            case VMP_NEW_INSTANCE: {
                const char *desc = vmp_pool_get((uint32_t)imm32);
                if (!desc) {
                    vmp_throw_runtime(env, "v5: new-instance bad pool idx");
                    (*env)->PopLocalFrame(env, NULL);
                    return NULL;
                }
                jclass cls = vmp_resolve_class(env, desc);
                if (!cls) {
                    (*env)->PopLocalFrame(env, NULL);
                    return NULL;
                }
                regs[dst].l = (*env)->AllocObject(env, cls);
                if ((*env)->ExceptionCheck(env)) {
                    (*env)->PopLocalFrame(env, NULL);
                    return NULL;
                }
                break;
            }
            case VMP_CHECK_CAST: {
                const char *desc = vmp_pool_get((uint32_t)imm32);
                if (!desc) break;
                if (regs[dst].l != NULL) {
                    jclass cls = vmp_resolve_class(env, desc);
                    if (cls && !(*env)->IsInstanceOf(env, regs[dst].l, cls)) {
                        vmp_throw(env, "java/lang/ClassCastException", desc);
                        (*env)->PopLocalFrame(env, NULL);
                        return NULL;
                    }
                }
                break;
            }
            case VMP_INSTANCE_OF: {
                const char *desc = vmp_pool_get((uint32_t)imm32);
                if (!desc) {
                    regs[dst].i = 0;
                    break;
                }
                jclass cls = vmp_resolve_class(env, desc);
                regs[dst].i = (cls && regs[src1].l != NULL &&
                               (*env)->IsInstanceOf(env, regs[src1].l, cls)) ? 1 : 0;
                break;
            }

            default: {
                char msg[96];
                snprintf(msg, sizeof(msg),
                         "v5: opcode %d not implemented (session 3 set is ~50 ops; "
                         "invokes / fields / arrays / switches land in session 3.5)",
                         real_op);
                vmp_throw_runtime(env, msg);
                (*env)->PopLocalFrame(env, NULL);
                return NULL;
            }
        }

        if (returned) break;
        pc = next_pc;
    }

    /* Auto-box the return value via the method's signature descriptor.
     * The signature is interned in the string pool at method_sig_idx;
     * the return-type portion lives after the last ')'. Reuse the v4
     * boxing pipeline (vmp_box_from_reg + vmp_box_cache) so v4 and v5
     * agree on autobox semantics. */
    jobject ret_obj = NULL;
    if (return_op == VMP_RETURN_OBJECT) {
        ret_obj = ret_reg.l;
    } else if (return_op != VMP_RETURN_VOID) {
        const char *sig = vmp_pool_get(method->method_sig_idx);
        const char *ret_desc = NULL;
        if (sig) {
            const char *paren = strrchr(sig, ')');
            if (paren) ret_desc = paren + 1;
        }
        if (ret_desc && ret_desc[0]) {
            ret_obj = vmp_box_from_reg(env, ret_desc, &ret_reg);
            if ((*env)->ExceptionCheck(env)) {
                (*env)->PopLocalFrame(env, NULL);
                return NULL;
            }
        }
    }
    return (*env)->PopLocalFrame(env, ret_obj);
}

static jobject vmp_run_interpreter(JNIEnv *env, const vmp_method_t *method,
                                    vmp_reg_t regs[VMP_MAX_REGS]) {
    /* v5 blobs route through their own dispatcher. */
    if (_active_ctx->blob_version == kVmpVersionV5) {
        return vmp_run_interpreter_v5(env, method, regs);
    }

    if (method->bytecode_off < 0 || method->bytecode_size < 0) {
        vmp_throw_runtime(env, "invalid VMP method bytecode range");
        return NULL;
    }
    if ((uint32_t) method->bytecode_off + (uint32_t) method->bytecode_size > _active_ctx->bytecode_size) {
        vmp_throw_runtime(env, "VMP method bytecode out of range");
        return NULL;
    }
    if ((method->bytecode_size % (int32_t) sizeof(vmp_insn_t)) != 0) {
        vmp_throw_runtime(env, "VMP bytecode size is not aligned");
        return NULL;
    }

    const vmp_insn_t *insns = (const vmp_insn_t *) (_active_ctx->bytecode + method->bytecode_off);
    const int insn_count = method->bytecode_size / (int32_t) sizeof(vmp_insn_t);

    /* Descramble operands if the method uses LFSR-based scrambling. */
    vmp_insn_t *descrambled_insns = NULL;
    if (method->op_obfs_seed != 0) {
        descrambled_insns = (vmp_insn_t *)alloca((size_t)insn_count * sizeof(vmp_insn_t));
        memcpy(descrambled_insns, insns, (size_t)insn_count * sizeof(vmp_insn_t));
        uint32_t lfsr = (uint32_t)(method->op_obfs_seed) | 1U;
        for (int di = 0; di < insn_count; di++) {
            lfsr = (lfsr >> 1) ^ ((lfsr & 1U) ? 0xD0000001U : 0U);
            uint32_t mask = lfsr;
            lfsr = (lfsr >> 1) ^ ((lfsr & 1U) ? 0xD0000001U : 0U);
            descrambled_insns[di].dst  ^= (mask & 0xFFU);
            descrambled_insns[di].src1 ^= ((mask >> 8) & 0xFFU);
            descrambled_insns[di].src2 ^= ((mask >> 16) & 0xFFU);
            descrambled_insns[di].imm  ^= (int32_t)(mask & 0xFFFFFFFFU);
        }
        insns = descrambled_insns;
    }

    /* Reserve a local-ref frame so that intermediate JNI local references
       (strings, class lookups, invoke results, etc.) are released in bulk
       when the method returns.  256 slots is generous for most methods. */
    if ((*env)->PushLocalFrame(env, 256) < 0) {
        vmp_throw_runtime(env, "PushLocalFrame failed in VMP interpreter");
        return NULL;
    }

    vmp_last_result_t last;
    memset(&last, 0, sizeof(last));
    last.kind = VMP_LAST_VOID;

    int pc = 0;
    int returned = 0;
    int return_op = VMP_RETURN_VOID;
    vmp_reg_t ret_reg;
    memset(&ret_reg, 0, sizeof(ret_reg));

    jobject caught_exception = NULL;

    uint32_t method_idx = (uint32_t)(method - _active_ctx->methods);
    const vmp_method_tries_t *method_tries =
        (method_idx < _active_ctx->method_count && _active_ctx->method_tries)
        ? &_active_ctx->method_tries[method_idx] : NULL;

    int step_budget = insn_count * 1024 + 1024;
    if (step_budget < 4096) step_budget = 4096;
    const int core_tier = vmp_clamp_tier(_active_ctx->core_tier);
    if (core_tier == VMP_TIER_COMPAT && step_budget < 8192) {
        step_budget = 8192;
    }

    /* Pre-decode shuffled opcodes → real opcodes for this method.
     * Eliminates _active_ctx->opcode_table indirection on every instruction. */
    uint8_t *decoded_ops = (uint8_t *)alloca(insn_count);
    for (int i = 0; i < insn_count; i++) {
        int op = _active_ctx->opcode_table[insns[i].opcode];
        decoded_ops[i] = (uint8_t)((op >= 0 && op < VMP_OP_COUNT) ? op : 0xFF);
    }

#if defined(__GNUC__) || defined(__clang__)
    /* Computed goto dispatch table.
     * Uses GCC/Clang labels-as-values extension for branch-predictor-friendly
     * indirect threading through the 150 VMP opcodes.  When the compiler does
     * not support this extension the standard switch-case dispatch below is
     * used as a portable fallback. */
    static const void *dispatch_table[VMP_OP_COUNT] = {
        [VMP_NOP]                   = &&VMP_NOP_LABEL,
        [VMP_MOVE]                  = &&VMP_MOVE_LABEL,
        [VMP_MOVE_WIDE]             = &&VMP_MOVE_LABEL,
        [VMP_MOVE_OBJECT]           = &&VMP_MOVE_LABEL,
        [VMP_MOVE_RESULT]           = &&VMP_MOVE_RESULT_LABEL,
        [VMP_MOVE_RESULT_WIDE]      = &&VMP_MOVE_RESULT_WIDE_LABEL,
        [VMP_MOVE_RESULT_OBJECT]    = &&VMP_MOVE_RESULT_OBJECT_LABEL,
        [VMP_MOVE_EXCEPTION]        = &&VMP_MOVE_EXCEPTION_LABEL,
        [VMP_RETURN_VOID]           = &&VMP_RETURN_VOID_LABEL,
        [VMP_RETURN]                = &&VMP_RETURN_LABEL,
        [VMP_RETURN_WIDE]           = &&VMP_RETURN_WIDE_LABEL,
        [VMP_RETURN_OBJECT]         = &&VMP_RETURN_OBJECT_LABEL,
        [VMP_CONST]                 = &&VMP_CONST_LABEL,
        [VMP_CONST_WIDE]            = &&VMP_CONST_WIDE_LABEL,
        [VMP_CONST_STRING]          = &&VMP_CONST_STRING_LABEL,
        [VMP_CONST_CLASS]           = &&VMP_CONST_CLASS_LABEL,
        [VMP_MONITOR_ENTER]         = &&VMP_MONITOR_ENTER_LABEL,
        [VMP_MONITOR_EXIT]          = &&VMP_MONITOR_EXIT_LABEL,
        [VMP_CHECK_CAST]            = &&VMP_CHECK_CAST_LABEL,
        [VMP_INSTANCE_OF]           = &&VMP_INSTANCE_OF_LABEL,
        [VMP_NEW_INSTANCE]          = &&VMP_NEW_INSTANCE_LABEL,
        [VMP_NEW_ARRAY]             = &&VMP_NEW_ARRAY_LABEL,
        [VMP_ARRAY_LENGTH]          = &&VMP_ARRAY_LENGTH_LABEL,
        [VMP_THROW]                 = &&VMP_THROW_LABEL,
        [VMP_GOTO]                  = &&VMP_GOTO_LABEL,
        [VMP_IF_EQ]                 = &&VMP_IF_EQ_LABEL,
        [VMP_IF_NE]                 = &&VMP_IF_NE_LABEL,
        [VMP_IF_LT]                 = &&VMP_IF_LT_LABEL,
        [VMP_IF_GE]                 = &&VMP_IF_GE_LABEL,
        [VMP_IF_GT]                 = &&VMP_IF_GT_LABEL,
        [VMP_IF_LE]                 = &&VMP_IF_LE_LABEL,
        [VMP_IF_EQZ]                = &&VMP_IF_EQZ_LABEL,
        [VMP_IF_NEZ]                = &&VMP_IF_NEZ_LABEL,
        [VMP_IF_LTZ]                = &&VMP_IF_LTZ_LABEL,
        [VMP_IF_GEZ]                = &&VMP_IF_GEZ_LABEL,
        [VMP_IF_GTZ]                = &&VMP_IF_GTZ_LABEL,
        [VMP_IF_LEZ]                = &&VMP_IF_LEZ_LABEL,
        [VMP_AGET]                  = &&VMP_AGET_LABEL,
        [VMP_AGET_WIDE]             = &&VMP_AGET_LABEL,
        [VMP_AGET_OBJECT]           = &&VMP_AGET_LABEL,
        [VMP_AGET_BOOLEAN]          = &&VMP_AGET_LABEL,
        [VMP_AGET_BYTE]             = &&VMP_AGET_LABEL,
        [VMP_AGET_CHAR]             = &&VMP_AGET_LABEL,
        [VMP_AGET_SHORT]            = &&VMP_AGET_LABEL,
        [VMP_APUT]                  = &&VMP_APUT_LABEL,
        [VMP_APUT_WIDE]             = &&VMP_APUT_LABEL,
        [VMP_APUT_OBJECT]           = &&VMP_APUT_LABEL,
        [VMP_APUT_BOOLEAN]          = &&VMP_APUT_LABEL,
        [VMP_APUT_BYTE]             = &&VMP_APUT_LABEL,
        [VMP_APUT_CHAR]             = &&VMP_APUT_LABEL,
        [VMP_APUT_SHORT]            = &&VMP_APUT_LABEL,
        [VMP_IGET]                  = &&VMP_IGET_LABEL,
        [VMP_IGET_WIDE]             = &&VMP_IGET_LABEL,
        [VMP_IGET_OBJECT]           = &&VMP_IGET_LABEL,
        [VMP_IGET_BOOLEAN]          = &&VMP_IGET_LABEL,
        [VMP_IGET_BYTE]             = &&VMP_IGET_LABEL,
        [VMP_IGET_CHAR]             = &&VMP_IGET_LABEL,
        [VMP_IGET_SHORT]            = &&VMP_IGET_LABEL,
        [VMP_IPUT]                  = &&VMP_IPUT_LABEL,
        [VMP_IPUT_WIDE]             = &&VMP_IPUT_LABEL,
        [VMP_IPUT_OBJECT]           = &&VMP_IPUT_LABEL,
        [VMP_IPUT_BOOLEAN]          = &&VMP_IPUT_LABEL,
        [VMP_IPUT_BYTE]             = &&VMP_IPUT_LABEL,
        [VMP_IPUT_CHAR]             = &&VMP_IPUT_LABEL,
        [VMP_IPUT_SHORT]            = &&VMP_IPUT_LABEL,
        [VMP_SGET]                  = &&VMP_SGET_LABEL,
        [VMP_SGET_WIDE]             = &&VMP_SGET_LABEL,
        [VMP_SGET_OBJECT]           = &&VMP_SGET_LABEL,
        [VMP_SGET_BOOLEAN]          = &&VMP_SGET_LABEL,
        [VMP_SGET_BYTE]             = &&VMP_SGET_LABEL,
        [VMP_SGET_CHAR]             = &&VMP_SGET_LABEL,
        [VMP_SGET_SHORT]            = &&VMP_SGET_LABEL,
        [VMP_SPUT]                  = &&VMP_SPUT_LABEL,
        [VMP_SPUT_WIDE]             = &&VMP_SPUT_LABEL,
        [VMP_SPUT_OBJECT]           = &&VMP_SPUT_LABEL,
        [VMP_SPUT_BOOLEAN]          = &&VMP_SPUT_LABEL,
        [VMP_SPUT_BYTE]             = &&VMP_SPUT_LABEL,
        [VMP_SPUT_CHAR]             = &&VMP_SPUT_LABEL,
        [VMP_SPUT_SHORT]            = &&VMP_SPUT_LABEL,
        [VMP_INVOKE_VIRTUAL]        = &&VMP_INVOKE_VIRTUAL_LABEL,
        [VMP_INVOKE_SUPER]          = &&VMP_INVOKE_VIRTUAL_LABEL,
        [VMP_INVOKE_DIRECT]         = &&VMP_INVOKE_VIRTUAL_LABEL,
        [VMP_INVOKE_STATIC]         = &&VMP_INVOKE_VIRTUAL_LABEL,
        [VMP_INVOKE_INTERFACE]      = &&VMP_INVOKE_VIRTUAL_LABEL,
        [VMP_INVOKE_CUSTOM]         = &&VMP_INVOKE_CUSTOM_LABEL,
        [VMP_INVOKE_POLYMORPHIC]    = &&VMP_INVOKE_POLYMORPHIC_LABEL,
        [VMP_NEG_INT]               = &&VMP_NEG_INT_LABEL,
        [VMP_NOT_INT]               = &&VMP_NOT_INT_LABEL,
        [VMP_NEG_LONG]              = &&VMP_NEG_LONG_LABEL,
        [VMP_NOT_LONG]              = &&VMP_NOT_LONG_LABEL,
        [VMP_NEG_FLOAT]             = &&VMP_NEG_FLOAT_LABEL,
        [VMP_NEG_DOUBLE]            = &&VMP_NEG_DOUBLE_LABEL,
        [VMP_INT_TO_LONG]           = &&VMP_INT_TO_LONG_LABEL,
        [VMP_INT_TO_FLOAT]          = &&VMP_INT_TO_FLOAT_LABEL,
        [VMP_INT_TO_DOUBLE]         = &&VMP_INT_TO_DOUBLE_LABEL,
        [VMP_LONG_TO_INT]           = &&VMP_LONG_TO_INT_LABEL,
        [VMP_LONG_TO_FLOAT]         = &&VMP_LONG_TO_FLOAT_LABEL,
        [VMP_LONG_TO_DOUBLE]        = &&VMP_LONG_TO_DOUBLE_LABEL,
        [VMP_FLOAT_TO_INT]          = &&VMP_FLOAT_TO_INT_LABEL,
        [VMP_FLOAT_TO_LONG]         = &&VMP_FLOAT_TO_LONG_LABEL,
        [VMP_FLOAT_TO_DOUBLE]       = &&VMP_FLOAT_TO_DOUBLE_LABEL,
        [VMP_DOUBLE_TO_INT]         = &&VMP_DOUBLE_TO_INT_LABEL,
        [VMP_DOUBLE_TO_LONG]        = &&VMP_DOUBLE_TO_LONG_LABEL,
        [VMP_DOUBLE_TO_FLOAT]       = &&VMP_DOUBLE_TO_FLOAT_LABEL,
        [VMP_INT_TO_BYTE]           = &&VMP_INT_TO_BYTE_LABEL,
        [VMP_INT_TO_CHAR]           = &&VMP_INT_TO_CHAR_LABEL,
        [VMP_INT_TO_SHORT]          = &&VMP_INT_TO_SHORT_LABEL,
        [VMP_ADD_INT]               = &&VMP_ADD_INT_LABEL,
        [VMP_SUB_INT]               = &&VMP_SUB_INT_LABEL,
        [VMP_MUL_INT]               = &&VMP_MUL_INT_LABEL,
        [VMP_DIV_INT]               = &&VMP_DIV_INT_LABEL,
        [VMP_REM_INT]               = &&VMP_REM_INT_LABEL,
        [VMP_AND_INT]               = &&VMP_AND_INT_LABEL,
        [VMP_OR_INT]                = &&VMP_OR_INT_LABEL,
        [VMP_XOR_INT]               = &&VMP_XOR_INT_LABEL,
        [VMP_SHL_INT]               = &&VMP_SHL_INT_LABEL,
        [VMP_SHR_INT]               = &&VMP_SHR_INT_LABEL,
        [VMP_USHR_INT]              = &&VMP_USHR_INT_LABEL,
        [VMP_ADD_LONG]              = &&VMP_ADD_LONG_LABEL,
        [VMP_SUB_LONG]              = &&VMP_SUB_LONG_LABEL,
        [VMP_MUL_LONG]              = &&VMP_MUL_LONG_LABEL,
        [VMP_DIV_LONG]              = &&VMP_DIV_LONG_LABEL,
        [VMP_REM_LONG]              = &&VMP_REM_LONG_LABEL,
        [VMP_AND_LONG]              = &&VMP_AND_LONG_LABEL,
        [VMP_OR_LONG]               = &&VMP_OR_LONG_LABEL,
        [VMP_XOR_LONG]              = &&VMP_XOR_LONG_LABEL,
        [VMP_SHL_LONG]              = &&VMP_SHL_LONG_LABEL,
        [VMP_SHR_LONG]              = &&VMP_SHR_LONG_LABEL,
        [VMP_USHR_LONG]             = &&VMP_USHR_LONG_LABEL,
        [VMP_ADD_FLOAT]             = &&VMP_ADD_FLOAT_LABEL,
        [VMP_SUB_FLOAT]             = &&VMP_SUB_FLOAT_LABEL,
        [VMP_MUL_FLOAT]             = &&VMP_MUL_FLOAT_LABEL,
        [VMP_DIV_FLOAT]             = &&VMP_DIV_FLOAT_LABEL,
        [VMP_REM_FLOAT]             = &&VMP_REM_FLOAT_LABEL,
        [VMP_ADD_DOUBLE]            = &&VMP_ADD_DOUBLE_LABEL,
        [VMP_SUB_DOUBLE]            = &&VMP_SUB_DOUBLE_LABEL,
        [VMP_MUL_DOUBLE]            = &&VMP_MUL_DOUBLE_LABEL,
        [VMP_DIV_DOUBLE]            = &&VMP_DIV_DOUBLE_LABEL,
        [VMP_REM_DOUBLE]            = &&VMP_REM_DOUBLE_LABEL,
        [VMP_CMP_LONG]              = &&VMP_CMP_LONG_LABEL,
        [VMP_CMPG_FLOAT]            = &&VMP_CMPG_FLOAT_LABEL,
        [VMP_CMPL_FLOAT]            = &&VMP_CMPL_FLOAT_LABEL,
        [VMP_CMPG_DOUBLE]           = &&VMP_CMPG_DOUBLE_LABEL,
        [VMP_CMPL_DOUBLE]           = &&VMP_CMPL_DOUBLE_LABEL,
        [VMP_PACKED_SWITCH]         = &&VMP_PACKED_SWITCH_LABEL,
        [VMP_SPARSE_SWITCH]         = &&VMP_SPARSE_SWITCH_LABEL,
        [VMP_FILL_ARRAY_DATA]       = &&VMP_FILL_ARRAY_DATA_LABEL,
        [VMP_FILLED_NEW_ARRAY]      = &&VMP_FILLED_NEW_ARRAY_LABEL,
        [VMP_INVOKE_ARGS]           = &&VMP_INVOKE_ARGS_LABEL,
        [VMP_CONST_WIDE_HI32]       = &&VMP_CONST_WIDE_HI32_LABEL,
        /* Alias opcodes use multi-shape duplicate semantic handlers where enabled. */
        [VMP_BINOP_ALIAS1] = &&VMP_BINOP_ALIAS1_LABEL,
        [VMP_BINOP_ALIAS2] = &&VMP_BINOP_ALIAS2_LABEL,
        [VMP_BINOP_ALIAS3] = &&VMP_BINOP_ALIAS3_LABEL,
        [VMP_BINOP_ALIAS4] = &&VMP_BINOP_ALIAS4_LABEL,
        [VMP_BINOP_ALIAS5] = &&VMP_BINOP_ALIAS5_LABEL,
        [VMP_BINOP_ALIAS6] = &&VMP_BINOP_ALIAS6_LABEL,
        [VMP_BINOP_ALIAS7] = &&VMP_BINOP_ALIAS7_LABEL,
        [VMP_BINOP_ALIAS8] = &&VMP_BINOP_ALIAS8_LABEL,
        [VMP_BINOP_ALIAS9] = &&VMP_BINOP_ALIAS9_LABEL,
        [VMP_BINOP_ALIAS10] = &&VMP_BINOP_ALIAS10_LABEL,
        [VMP_UNOP_ALIAS1] = &&VMP_SUB_ALIAS1_LABEL,
        [VMP_UNOP_ALIAS2] = &&VMP_SUB_ALIAS2_LABEL,
        [VMP_UNOP_ALIAS3] = &&VMP_SUB_ALIAS3_LABEL,
        [VMP_UNOP_ALIAS4] = &&VMP_AND_ALIAS1_LABEL,
        [VMP_UNOP_ALIAS5] = &&VMP_AND_ALIAS2_LABEL,
        [VMP_BINOP_LIT_ALIAS1] = &&VMP_BINOP_LIT_ALIAS1_LABEL,
        [VMP_BINOP_LIT_ALIAS2] = &&VMP_BINOP_LIT_ALIAS2_LABEL,
        [VMP_BINOP_LIT_ALIAS3] = &&VMP_BINOP_LIT_ALIAS3_LABEL,
        [VMP_BINOP_LIT_ALIAS4] = &&VMP_BINOP_LIT_ALIAS4_LABEL,
        [VMP_BINOP_LIT_ALIAS5] = &&VMP_BINOP_LIT_ALIAS5_LABEL,
        [VMP_BINOP_LIT_ALIAS6] = &&VMP_BINOP_LIT_ALIAS6_LABEL,
        [VMP_BINOP_LIT_ALIAS7] = &&VMP_BINOP_LIT_ALIAS7_LABEL,
        [VMP_BINOP_LIT_ALIAS8] = &&VMP_BINOP_LIT_ALIAS8_LABEL,
        [VMP_IF_ALIAS1] = &&VMP_OR_ALIAS1_LABEL,
        [VMP_IF_ALIAS2] = &&VMP_OR_ALIAS2_LABEL,
        [VMP_IF_ALIAS3] = &&VMP_XOR_ALIAS1_LABEL,
        [VMP_IF_ALIAS4] = &&VMP_XOR_ALIAS2_LABEL,
        [VMP_IF_ALIAS5] = &&VMP_IF_EQ_LABEL,
        [VMP_IF_ALIAS6] = &&VMP_IF_EQ_LABEL,
        [VMP_IFZ_ALIAS1] = &&VMP_IF_EQZ_LABEL,
        [VMP_IFZ_ALIAS2] = &&VMP_IF_EQZ_LABEL,
        [VMP_IFZ_ALIAS3] = &&VMP_IF_EQZ_LABEL,
        [VMP_IFZ_ALIAS4] = &&VMP_IF_EQZ_LABEL,
        [VMP_IFZ_ALIAS5] = &&VMP_IF_EQZ_LABEL,
        [VMP_IFZ_ALIAS6] = &&VMP_IF_EQZ_LABEL,
        [VMP_AGET_ALIAS1] = &&VMP_AGET_LABEL,
        [VMP_AGET_ALIAS2] = &&VMP_AGET_LABEL,
        [VMP_AGET_ALIAS3] = &&VMP_AGET_LABEL,
        [VMP_AGET_ALIAS4] = &&VMP_AGET_LABEL,
        [VMP_APUT_ALIAS1] = &&VMP_APUT_LABEL,
        [VMP_APUT_ALIAS2] = &&VMP_APUT_LABEL,
        [VMP_APUT_ALIAS3] = &&VMP_APUT_LABEL,
        [VMP_APUT_ALIAS4] = &&VMP_APUT_LABEL,
        [VMP_IGET_ALIAS1] = &&VMP_IGET_LABEL,
        [VMP_IGET_ALIAS2] = &&VMP_IGET_LABEL,
        [VMP_IGET_ALIAS3] = &&VMP_IGET_LABEL,
        [VMP_IPUT_ALIAS1] = &&VMP_IPUT_LABEL,
        [VMP_IPUT_ALIAS2] = &&VMP_IPUT_LABEL,
        [VMP_IPUT_ALIAS3] = &&VMP_IPUT_LABEL,
        [VMP_SGET_SPUT_ALIAS1] = &&VMP_SGET_LABEL,
    };

    if (VMP_UNLIKELY(!(pc >= 0 && pc < insn_count))) goto vmp_cleanup;
    goto *dispatch_table[decoded_ops[0]];

    /* ---- Opcode handlers (computed goto targets) ---- */

VMP_NOP_LABEL:
    goto vmp_next_insn;

VMP_MOVE_LABEL:
    regs[insns[pc].dst] = regs[insns[pc].src1];
    goto vmp_next_insn;

VMP_MOVE_RESULT_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    switch (last.kind) {
        case VMP_LAST_INT: VMP_RSET_I(regs[in->dst], last.v.i); break;
        case VMP_LAST_LONG: VMP_RSET_I(regs[in->dst], (jint) last.v.j); break;
        case VMP_LAST_FLOAT: VMP_RSET_F(regs[in->dst], last.v.f); break;
        case VMP_LAST_DOUBLE: VMP_RSET_I(regs[in->dst], (jint) last.v.d); break;
        case VMP_LAST_OBJECT: regs[in->dst].l = last.v.l; break;
        default: VMP_RSET_I(regs[in->dst], 0); break;
    }
    last.kind = VMP_LAST_VOID;
    goto vmp_next_insn;
}

VMP_MOVE_RESULT_WIDE_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    if (last.kind == VMP_LAST_LONG) {
        regs[in->dst].j = last.v.j;
    } else if (last.kind == VMP_LAST_DOUBLE) {
        regs[in->dst].d = last.v.d;
    } else {
        regs[in->dst].j = 0;
    }
    if (in->dst + 1 < VMP_MAX_REGS) regs[in->dst + 1] = regs[in->dst];
    last.kind = VMP_LAST_VOID;
    goto vmp_next_insn;
}

VMP_MOVE_RESULT_OBJECT_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    regs[in->dst].l = (last.kind == VMP_LAST_OBJECT) ? last.v.l : NULL;
    last.kind = VMP_LAST_VOID;
    goto vmp_next_insn;
}

VMP_MOVE_EXCEPTION_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    if (caught_exception) {
        regs[in->dst].l = caught_exception;
        caught_exception = NULL;
    } else if ((*env)->ExceptionCheck(env)) {
        jobject ex = (*env)->ExceptionOccurred(env);
        (*env)->ExceptionClear(env);
        regs[in->dst].l = ex;
    } else {
        regs[in->dst].l = NULL;
    }
    goto vmp_next_insn;
}

VMP_RETURN_VOID_LABEL:
    return_op = VMP_RETURN_VOID;
    returned = 1;
    goto vmp_cleanup;

VMP_RETURN_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    ret_reg = regs[in->dst];
    return_op = VMP_RETURN;
    returned = 1;
    goto vmp_cleanup;
}

VMP_RETURN_WIDE_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    ret_reg = regs[in->dst];
    return_op = VMP_RETURN_WIDE;
    returned = 1;
    goto vmp_cleanup;
}

VMP_RETURN_OBJECT_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    ret_reg = regs[in->dst];
    return_op = VMP_RETURN_OBJECT;
    returned = 1;
    goto vmp_cleanup;
}

VMP_CONST_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    VMP_RSET_I(regs[in->dst], in->imm);
    goto vmp_next_insn;
}

VMP_CONST_WIDE_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    int64_t v = (int64_t) in->imm;
    if (pc + 1 < insn_count) {
        int next_op = decoded_ops[pc + 1];
        if (next_op == VMP_CONST_WIDE_HI32) {
            uint64_t lo = (uint32_t) in->imm;
            uint64_t hi = (uint32_t) insns[pc + 1].imm;
            v = (int64_t) (lo | (hi << 32));
            regs[in->dst].j = v;
            if (in->dst + 1 < VMP_MAX_REGS) regs[in->dst + 1] = regs[in->dst];
            pc += 2;
            goto vmp_dispatch;
        }
    }
    regs[in->dst].j = v;
    if (in->dst + 1 < VMP_MAX_REGS) regs[in->dst + 1] = regs[in->dst];
    goto vmp_next_insn;
}

VMP_CONST_STRING_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    const char *s = vmp_pool_get((uint32_t) in->imm);
    regs[in->dst].l = s ? (*env)->NewStringUTF(env, s) : NULL;
    goto vmp_next_insn;
}

VMP_CONST_CLASS_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    const char *desc = vmp_pool_get((uint32_t) in->imm);
    regs[in->dst].l = desc ? vmp_resolve_class(env, desc) : NULL;
    goto vmp_next_insn;
}

VMP_MONITOR_ENTER_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    if ((*env)->MonitorEnter(env, regs[in->dst].l) != JNI_OK) {
        vmp_throw_runtime(env, "monitor-enter failed");
    }
    goto vmp_next_insn;
}

VMP_MONITOR_EXIT_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    if ((*env)->MonitorExit(env, regs[in->dst].l) != JNI_OK) {
        vmp_throw_runtime(env, "monitor-exit failed");
    }
    goto vmp_next_insn;
}

VMP_CHECK_CAST_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    const char *desc = vmp_pool_get((uint32_t) in->imm);
    jobject obj = regs[in->dst].l;
    if (obj != NULL && desc != NULL) {
        jclass cls = vmp_resolve_class(env, desc);
        if (!cls) goto vmp_next_insn;
        if (!(*env)->IsInstanceOf(env, obj, cls)) {
            (*env)->DeleteLocalRef(env, cls);
            vmp_throw(env, "java/lang/ClassCastException", "check-cast failed");
            goto vmp_next_insn;
        }
        (*env)->DeleteLocalRef(env, cls);
    }
    goto vmp_next_insn;
}

VMP_INSTANCE_OF_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    const char *desc = vmp_pool_get((uint32_t) in->imm);
    jobject obj = regs[in->src1].l;
    jclass cls = desc ? vmp_resolve_class(env, desc) : NULL;
    VMP_RSET_I(regs[in->dst], (obj && cls && (*env)->IsInstanceOf(env, obj, cls)) ? 1 : 0);
    if (cls) (*env)->DeleteLocalRef(env, cls);
    goto vmp_next_insn;
}

VMP_NEW_INSTANCE_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    const char *desc = vmp_pool_get((uint32_t) in->imm);
    jclass cls = desc ? vmp_resolve_class(env, desc) : NULL;
    regs[in->dst].l = cls ? (*env)->AllocObject(env, cls) : NULL;
    if (cls) (*env)->DeleteLocalRef(env, cls);
    goto vmp_next_insn;
}

VMP_NEW_ARRAY_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    const char *desc = vmp_pool_get((uint32_t) in->imm);
    regs[in->dst].l = desc ? vmp_new_array(env, desc, regs[in->src1].i) : NULL;
    goto vmp_next_insn;
}

VMP_ARRAY_LENGTH_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    VMP_RSET_I(regs[in->dst], regs[in->src1].l ? (*env)->GetArrayLength(env, (jarray) regs[in->src1].l) : 0);
    goto vmp_next_insn;
}

VMP_THROW_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    if (regs[in->dst].l) {
        (*env)->Throw(env, (jthrowable) regs[in->dst].l);
    } else {
        vmp_throw_runtime(env, "throw null");
    }
    returned = 1;
    return_op = VMP_RETURN_VOID;
    goto vmp_cleanup;
}

VMP_GOTO_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    pc += in->imm;
    goto vmp_dispatch;
}

VMP_IF_EQ_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    if (vmp_branch_cond_eq(regs[in->dst], regs[in->src1])) { pc += in->imm; goto vmp_dispatch; }
    goto vmp_next_insn;
}
VMP_IF_NE_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    if (vmp_branch_cond_ne(regs[in->dst], regs[in->src1])) { pc += in->imm; goto vmp_dispatch; }
    goto vmp_next_insn;
}
VMP_IF_LT_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    if (regs[in->dst].i < regs[in->src1].i) { pc += in->imm; goto vmp_dispatch; }
    goto vmp_next_insn;
}
VMP_IF_GE_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    if (regs[in->dst].i >= regs[in->src1].i) { pc += in->imm; goto vmp_dispatch; }
    goto vmp_next_insn;
}
VMP_IF_GT_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    if (regs[in->dst].i > regs[in->src1].i) { pc += in->imm; goto vmp_dispatch; }
    goto vmp_next_insn;
}
VMP_IF_LE_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    if (regs[in->dst].i <= regs[in->src1].i) { pc += in->imm; goto vmp_dispatch; }
    goto vmp_next_insn;
}

VMP_IF_EQZ_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    if (regs[in->dst].j == 0) { pc += in->imm; goto vmp_dispatch; }
    goto vmp_next_insn;
}
VMP_IF_NEZ_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    if (regs[in->dst].j != 0) { pc += in->imm; goto vmp_dispatch; }
    goto vmp_next_insn;
}
VMP_IF_LTZ_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    if (regs[in->dst].i < 0) { pc += in->imm; goto vmp_dispatch; }
    goto vmp_next_insn;
}
VMP_IF_GEZ_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    if (regs[in->dst].i >= 0) { pc += in->imm; goto vmp_dispatch; }
    goto vmp_next_insn;
}
VMP_IF_GTZ_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    if (regs[in->dst].i > 0) { pc += in->imm; goto vmp_dispatch; }
    goto vmp_next_insn;
}
VMP_IF_LEZ_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    if (regs[in->dst].i <= 0) { pc += in->imm; goto vmp_dispatch; }
    goto vmp_next_insn;
}

VMP_AGET_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    vmp_array_get(env, vmp_kind_from_aget_op(decoded_ops[pc]), regs, in->dst, in->src1, in->src2);
    goto vmp_next_insn;
}

VMP_APUT_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    vmp_array_put(env, vmp_kind_from_aput_op(decoded_ops[pc]), regs, in->dst, in->src1, in->src2);
    goto vmp_next_insn;
}

VMP_IGET_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    const char *ref = vmp_pool_get((uint32_t) in->imm);
    if (ref) (void) vmp_field_get(env, vmp_kind_from_iget_op(decoded_ops[pc]), 0, regs, in->dst, in->src1, ref);
    goto vmp_next_insn;
}

VMP_IPUT_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    const char *ref = vmp_pool_get((uint32_t) in->imm);
    if (ref) (void) vmp_field_put(env, vmp_kind_from_iput_op(decoded_ops[pc]), 0, regs, in->dst, in->src1, ref);
    goto vmp_next_insn;
}

VMP_SGET_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    const char *ref = vmp_pool_get((uint32_t) in->imm);
    if (ref) (void) vmp_field_get(env, vmp_kind_from_sget_op(decoded_ops[pc]), 1, regs, in->dst, 0, ref);
    goto vmp_next_insn;
}

VMP_SPUT_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    const char *ref = vmp_pool_get((uint32_t) in->imm);
    if (ref) (void) vmp_field_put(env, vmp_kind_from_sput_op(decoded_ops[pc]), 1, regs, in->dst, 0, ref);
    goto vmp_next_insn;
}

VMP_INVOKE_VIRTUAL_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    if (pc + 1 >= insn_count) {
        vmp_throw_runtime(env, "invoke missing INVOKE_ARGS");
        returned = 1;
        goto vmp_cleanup;
    }
    const vmp_insn_t *args_in = &insns[pc + 1];
    int args_op = decoded_ops[pc + 1];
    if (args_op != VMP_INVOKE_ARGS) {
        vmp_throw_runtime(env, "invoke arg format mismatch");
        returned = 1;
        goto vmp_cleanup;
    }
    uint8_t regs_words[256];
    int arg_words = in->dst;
    if (arg_words < 0 || arg_words > 255) {
        vmp_throw_runtime(env, "invoke arg count invalid");
        returned = 1;
        goto vmp_cleanup;
    }
    if (vmp_collect_invoke_regs(args_in, arg_words, regs_words, 256) != 0) {
        vmp_throw_runtime(env, "invoke arg decode failed");
        returned = 1;
        goto vmp_cleanup;
    }
    const char *ref = vmp_pool_get((uint32_t) in->imm);
    if (!ref || vmp_invoke_ref(env, decoded_ops[pc], ref, regs_words, arg_words, regs, &last) != 0) {
        if (!(*env)->ExceptionCheck(env)) {
            vmp_throw_runtime(env, "invoke failed");
        }
        returned = 1;
        goto vmp_cleanup;
    }
    pc += 2;
    goto vmp_dispatch;
}

VMP_INVOKE_CUSTOM_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    if (pc + 1 >= insn_count) {
        vmp_throw_runtime(env, "invoke-custom missing INVOKE_ARGS");
        returned = 1;
        goto vmp_cleanup;
    }
    const vmp_insn_t *args_in = &insns[pc + 1];
    int args_op = decoded_ops[pc + 1];
    if (args_op != VMP_INVOKE_ARGS) {
        vmp_throw_runtime(env, "invoke-custom arg format mismatch");
        returned = 1;
        goto vmp_cleanup;
    }
    uint8_t regs_words[256];
    int arg_words = in->dst;
    if (arg_words < 0 || arg_words > 255) {
        vmp_throw_runtime(env, "invoke-custom arg count invalid");
        returned = 1;
        goto vmp_cleanup;
    }
    if (vmp_collect_invoke_regs(args_in, arg_words, regs_words, 256) != 0) {
        vmp_throw_runtime(env, "invoke-custom arg decode failed");
        returned = 1;
        goto vmp_cleanup;
    }
    const char *cs_ref = vmp_pool_get((uint32_t) in->imm);
    if (!cs_ref || strncmp(cs_ref, "@cs:", 4) != 0) {
        vmp_throw_runtime(env, "invoke-custom bad ref");
        returned = 1;
        goto vmp_cleanup;
    }
    const char *payload = cs_ref + 4;
    const char *pipe1 = strchr(payload, '|');
    if (!pipe1) {
        vmp_throw_runtime(env, "invoke-custom malformed ref");
        returned = 1;
        goto vmp_cleanup;
    }
    const char *target_ref = pipe1 + 1;
    const char *pipe2 = strchr(target_ref, '|');
    char target_buf[512];
    int tlen = pipe2 ? (int)(pipe2 - target_ref) : (int)strlen(target_ref);
    if (tlen >= (int)sizeof(target_buf)) tlen = (int)sizeof(target_buf) - 1;
    memcpy(target_buf, target_ref, tlen);
    target_buf[tlen] = '\0';
    if (vmp_invoke_ref(env, VMP_INVOKE_STATIC, target_buf,
                       regs_words, arg_words, regs, &last) != 0) {
        if (!(*env)->ExceptionCheck(env)) {
            vmp_throw_runtime(env, "invoke-custom target call failed");
        }
        returned = 1;
        goto vmp_cleanup;
    }
    pc += 2;
    goto vmp_dispatch;
}

VMP_INVOKE_POLYMORPHIC_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    if (pc + 1 >= insn_count) {
        vmp_throw_runtime(env, "invoke-polymorphic missing INVOKE_ARGS");
        returned = 1;
        goto vmp_cleanup;
    }
    const vmp_insn_t *args_in = &insns[pc + 1];
    int args_op = decoded_ops[pc + 1];
    if (args_op != VMP_INVOKE_ARGS) {
        vmp_throw_runtime(env, "invoke-polymorphic arg format mismatch");
        returned = 1;
        goto vmp_cleanup;
    }
    uint8_t regs_words[256];
    int arg_words = in->dst;
    if (arg_words < 0 || arg_words > 255) {
        vmp_throw_runtime(env, "invoke-polymorphic arg count invalid");
        returned = 1;
        goto vmp_cleanup;
    }
    if (vmp_collect_invoke_regs(args_in, arg_words, regs_words, 256) != 0) {
        vmp_throw_runtime(env, "invoke-polymorphic arg decode failed");
        returned = 1;
        goto vmp_cleanup;
    }
    const char *ref = vmp_pool_get((uint32_t) in->imm);
    if (!ref || vmp_invoke_ref(env, VMP_INVOKE_VIRTUAL, ref,
                               regs_words, arg_words, regs, &last) != 0) {
        if (!(*env)->ExceptionCheck(env)) {
            vmp_throw_runtime(env, "invoke-polymorphic failed");
        }
        returned = 1;
        goto vmp_cleanup;
    }
    pc += 2;
    goto vmp_dispatch;
}

VMP_NEG_INT_LABEL:  { const vmp_insn_t *in = &insns[pc]; VMP_RSET_I(regs[in->dst], -regs[in->src1].i); goto vmp_next_insn; }
VMP_NOT_INT_LABEL:  { const vmp_insn_t *in = &insns[pc]; VMP_RSET_I(regs[in->dst], ~regs[in->src1].i); goto vmp_next_insn; }
VMP_NEG_LONG_LABEL: { const vmp_insn_t *in = &insns[pc]; regs[in->dst].j = -regs[in->src1].j; goto vmp_next_insn; }
VMP_NOT_LONG_LABEL: { const vmp_insn_t *in = &insns[pc]; regs[in->dst].j = ~regs[in->src1].j; goto vmp_next_insn; }
VMP_NEG_FLOAT_LABEL: { const vmp_insn_t *in = &insns[pc]; VMP_RSET_F(regs[in->dst], -regs[in->src1].f); goto vmp_next_insn; }
VMP_NEG_DOUBLE_LABEL: { const vmp_insn_t *in = &insns[pc]; regs[in->dst].d = -regs[in->src1].d; goto vmp_next_insn; }

VMP_INT_TO_LONG_LABEL: { const vmp_insn_t *in = &insns[pc]; regs[in->dst].j = (jlong) regs[in->src1].i; goto vmp_next_insn; }
VMP_INT_TO_FLOAT_LABEL: { const vmp_insn_t *in = &insns[pc]; VMP_RSET_F(regs[in->dst], (jfloat) regs[in->src1].i); goto vmp_next_insn; }
VMP_INT_TO_DOUBLE_LABEL: { const vmp_insn_t *in = &insns[pc]; regs[in->dst].d = (jdouble) regs[in->src1].i; goto vmp_next_insn; }
VMP_LONG_TO_INT_LABEL: { const vmp_insn_t *in = &insns[pc]; VMP_RSET_I(regs[in->dst], (jint) regs[in->src1].j); goto vmp_next_insn; }
VMP_LONG_TO_FLOAT_LABEL: { const vmp_insn_t *in = &insns[pc]; VMP_RSET_F(regs[in->dst], (jfloat) regs[in->src1].j); goto vmp_next_insn; }
VMP_LONG_TO_DOUBLE_LABEL: { const vmp_insn_t *in = &insns[pc]; regs[in->dst].d = (jdouble) regs[in->src1].j; goto vmp_next_insn; }
VMP_FLOAT_TO_INT_LABEL: { const vmp_insn_t *in = &insns[pc]; VMP_RSET_I(regs[in->dst], (jint) regs[in->src1].f); goto vmp_next_insn; }
VMP_FLOAT_TO_LONG_LABEL: { const vmp_insn_t *in = &insns[pc]; regs[in->dst].j = (jlong) regs[in->src1].f; goto vmp_next_insn; }
VMP_FLOAT_TO_DOUBLE_LABEL: { const vmp_insn_t *in = &insns[pc]; regs[in->dst].d = (jdouble) regs[in->src1].f; goto vmp_next_insn; }
VMP_DOUBLE_TO_INT_LABEL: { const vmp_insn_t *in = &insns[pc]; VMP_RSET_I(regs[in->dst], (jint) regs[in->src1].d); goto vmp_next_insn; }
VMP_DOUBLE_TO_LONG_LABEL: { const vmp_insn_t *in = &insns[pc]; regs[in->dst].j = (jlong) regs[in->src1].d; goto vmp_next_insn; }
VMP_DOUBLE_TO_FLOAT_LABEL: { const vmp_insn_t *in = &insns[pc]; VMP_RSET_F(regs[in->dst], (jfloat) regs[in->src1].d); goto vmp_next_insn; }
VMP_INT_TO_BYTE_LABEL: { const vmp_insn_t *in = &insns[pc]; VMP_RSET_I(regs[in->dst], (jbyte) regs[in->src1].i); goto vmp_next_insn; }
VMP_INT_TO_CHAR_LABEL: { const vmp_insn_t *in = &insns[pc]; VMP_RSET_I(regs[in->dst], (jchar) regs[in->src1].i); goto vmp_next_insn; }
VMP_INT_TO_SHORT_LABEL: { const vmp_insn_t *in = &insns[pc]; VMP_RSET_I(regs[in->dst], (jshort) regs[in->src1].i); goto vmp_next_insn; }

#define VMP_BINOP_INT_LABEL(label_suffix, op, rhs_expr) \
VMP_##label_suffix##_LABEL: { \
    const vmp_insn_t *in = &insns[pc]; \
    int32_t rhs_ = rhs_expr; \
    int32_t lhs_ = vmp_bin_lhs_i(in, regs); \
    VMP_RSET_I(regs[in->dst], lhs_ op rhs_); \
    goto vmp_next_insn; \
}

#define VMP_BINOP_LONG_LABEL(label_suffix, op) \
VMP_##label_suffix##_LABEL: { \
    const vmp_insn_t *in = &insns[pc]; \
    int64_t rhs_ = vmp_bin_rhs_j(in, regs); \
    int64_t lhs_ = vmp_bin_lhs_j(in, regs); \
    regs[in->dst].j = lhs_ op rhs_; \
    goto vmp_next_insn; \
}

#define VMP_ADD_INT_ALIAS_U32(label_suffix) \
VMP_##label_suffix##_LABEL: { \
    const vmp_insn_t *in = &insns[pc]; \
    uint32_t lhs_ = (uint32_t)vmp_bin_lhs_i(in, regs); \
    uint32_t rhs_ = (uint32_t)vmp_bin_rhs_i(in, regs); \
    VMP_RSET_I(regs[in->dst], (jint)(lhs_ + rhs_)); \
    goto vmp_next_insn; \
}

#define VMP_ADD_INT_ALIAS_COMMUTE(label_suffix) \
VMP_##label_suffix##_LABEL: { \
    const vmp_insn_t *in = &insns[pc]; \
    uint32_t lhs_ = (uint32_t)vmp_bin_lhs_i(in, regs); \
    uint32_t rhs_ = (uint32_t)vmp_bin_rhs_i(in, regs); \
    VMP_RSET_I(regs[in->dst], (jint)(rhs_ + lhs_)); \
    goto vmp_next_insn; \
}

#define VMP_ADD_INT_ALIAS_WIDE(label_suffix) \
VMP_##label_suffix##_LABEL: { \
    const vmp_insn_t *in = &insns[pc]; \
    uint32_t lhs_ = (uint32_t)vmp_bin_lhs_i(in, regs); \
    uint32_t rhs_ = (uint32_t)vmp_bin_rhs_i(in, regs); \
    VMP_RSET_I(regs[in->dst], (jint)(uint32_t)((uint64_t)lhs_ + (uint64_t)rhs_)); \
    goto vmp_next_insn; \
}

#define VMP_ADD_INT_ALIAS_SALTED(label_suffix) \
VMP_##label_suffix##_LABEL: { \
    const vmp_insn_t *in = &insns[pc]; \
    uint32_t lhs_ = (uint32_t)vmp_bin_lhs_i(in, regs); \
    uint32_t rhs_ = (uint32_t)vmp_bin_rhs_i(in, regs); \
    uint32_t salt_ = ((uint32_t)in->dst << 24) ^ ((uint32_t)in->src1 << 16) ^ ((uint32_t)in->src2 << 8) ^ (uint32_t)in->opcode ^ 0x9E3779B9u; \
    VMP_RSET_I(regs[in->dst], (jint)((lhs_ + salt_) + rhs_ - salt_)); \
    goto vmp_next_insn; \
}

#define VMP_ADD_INT_ALIAS_SPLIT16(label_suffix) \
VMP_##label_suffix##_LABEL: { \
    const vmp_insn_t *in = &insns[pc]; \
    uint32_t lhs_ = (uint32_t)vmp_bin_lhs_i(in, regs); \
    uint32_t rhs_ = (uint32_t)vmp_bin_rhs_i(in, regs); \
    uint32_t lo_ = (lhs_ & 0x0000FFFFu) + (rhs_ & 0x0000FFFFu); \
    uint32_t hi_ = (lhs_ & 0xFFFF0000u) + (rhs_ & 0xFFFF0000u); \
    VMP_RSET_I(regs[in->dst], (jint)(hi_ + lo_)); \
    goto vmp_next_insn; \
}

#define VMP_ADD_INT_ALIAS_NEGSUB(label_suffix) \
VMP_##label_suffix##_LABEL: { \
    const vmp_insn_t *in = &insns[pc]; \
    uint32_t lhs_ = (uint32_t)vmp_bin_lhs_i(in, regs); \
    uint32_t rhs_ = (uint32_t)vmp_bin_rhs_i(in, regs); \
    VMP_RSET_I(regs[in->dst], (jint)(lhs_ - ((~rhs_) + 1u))); \
    goto vmp_next_insn; \
}

#define VMP_ADD_INT_ALIAS_VOLATILE_ZERO(label_suffix) \
VMP_##label_suffix##_LABEL: { \
    const vmp_insn_t *in = &insns[pc]; \
    uint32_t lhs_ = (uint32_t)vmp_bin_lhs_i(in, regs); \
    uint32_t rhs_ = (uint32_t)vmp_bin_rhs_i(in, regs); \
    volatile uint32_t zero_ = ((uint32_t)in->opcode ^ (uint32_t)in->opcode); \
    VMP_RSET_I(regs[in->dst], (jint)((lhs_ + rhs_) ^ zero_)); \
    goto vmp_next_insn; \
}

#define VMP_ADD_INT_ALIAS_SPLIT_RHS(label_suffix) \
VMP_##label_suffix##_LABEL: { \
    const vmp_insn_t *in = &insns[pc]; \
    uint32_t lhs_ = (uint32_t)vmp_bin_lhs_i(in, regs); \
    uint32_t rhs_ = (uint32_t)vmp_bin_rhs_i(in, regs); \
    VMP_RSET_I(regs[in->dst], (jint)((lhs_ + (rhs_ & 0x00FF00FFu)) + (rhs_ & 0xFF00FF00u))); \
    goto vmp_next_insn; \
}

#define VMP_SUB_INT_ALIAS_U32(label_suffix) \
VMP_##label_suffix##_LABEL: { \
    const vmp_insn_t *in = &insns[pc]; \
    uint32_t lhs_ = (uint32_t)vmp_bin_lhs_i(in, regs); \
    uint32_t rhs_ = (uint32_t)vmp_bin_rhs_i(in, regs); \
    VMP_RSET_I(regs[in->dst], (jint)(lhs_ - rhs_)); \
    goto vmp_next_insn; \
}

#define VMP_SUB_INT_ALIAS_ADDNEG(label_suffix) \
VMP_##label_suffix##_LABEL: { \
    const vmp_insn_t *in = &insns[pc]; \
    uint32_t lhs_ = (uint32_t)vmp_bin_lhs_i(in, regs); \
    uint32_t rhs_ = (uint32_t)vmp_bin_rhs_i(in, regs); \
    VMP_RSET_I(regs[in->dst], (jint)(lhs_ + ((~rhs_) + 1u))); \
    goto vmp_next_insn; \
}

#define VMP_SUB_INT_ALIAS_SALTED(label_suffix) \
VMP_##label_suffix##_LABEL: { \
    const vmp_insn_t *in = &insns[pc]; \
    uint32_t lhs_ = (uint32_t)vmp_bin_lhs_i(in, regs); \
    uint32_t rhs_ = (uint32_t)vmp_bin_rhs_i(in, regs); \
    uint32_t salt_ = ((uint32_t)in->dst << 21) ^ ((uint32_t)in->src1 << 13) ^ ((uint32_t)in->src2 << 5) ^ 0xA5A5C3C3u; \
    VMP_RSET_I(regs[in->dst], (jint)((lhs_ + salt_) - rhs_ - salt_)); \
    goto vmp_next_insn; \
}

#define VMP_AND_INT_ALIAS_DEMORGAN(label_suffix) \
VMP_##label_suffix##_LABEL: { \
    const vmp_insn_t *in = &insns[pc]; \
    uint32_t lhs_ = (uint32_t)vmp_bin_lhs_i(in, regs); \
    uint32_t rhs_ = (uint32_t)vmp_bin_rhs_i(in, regs); \
    VMP_RSET_I(regs[in->dst], (jint)(~((~lhs_) | (~rhs_)))); \
    goto vmp_next_insn; \
}

#define VMP_AND_INT_ALIAS_MASKED(label_suffix) \
VMP_##label_suffix##_LABEL: { \
    const vmp_insn_t *in = &insns[pc]; \
    uint32_t lhs_ = (uint32_t)vmp_bin_lhs_i(in, regs); \
    uint32_t rhs_ = (uint32_t)vmp_bin_rhs_i(in, regs); \
    volatile uint32_t all_ = 0xFFFFFFFFu; \
    VMP_RSET_I(regs[in->dst], (jint)((lhs_ & all_) & rhs_)); \
    goto vmp_next_insn; \
}

#define VMP_OR_INT_ALIAS_DEMORGAN(label_suffix) \
VMP_##label_suffix##_LABEL: { \
    const vmp_insn_t *in = &insns[pc]; \
    uint32_t lhs_ = (uint32_t)vmp_bin_lhs_i(in, regs); \
    uint32_t rhs_ = (uint32_t)vmp_bin_rhs_i(in, regs); \
    VMP_RSET_I(regs[in->dst], (jint)(~((~lhs_) & (~rhs_)))); \
    goto vmp_next_insn; \
}

#define VMP_OR_INT_ALIAS_SPLIT(label_suffix) \
VMP_##label_suffix##_LABEL: { \
    const vmp_insn_t *in = &insns[pc]; \
    uint32_t lhs_ = (uint32_t)vmp_bin_lhs_i(in, regs); \
    uint32_t rhs_ = (uint32_t)vmp_bin_rhs_i(in, regs); \
    uint32_t lo_ = (lhs_ | rhs_) & 0x00FF00FFu; \
    uint32_t hi_ = (lhs_ | rhs_) & 0xFF00FF00u; \
    VMP_RSET_I(regs[in->dst], (jint)(lo_ | hi_)); \
    goto vmp_next_insn; \
}

#define VMP_XOR_INT_ALIAS_ORAND(label_suffix) \
VMP_##label_suffix##_LABEL: { \
    const vmp_insn_t *in = &insns[pc]; \
    uint32_t lhs_ = (uint32_t)vmp_bin_lhs_i(in, regs); \
    uint32_t rhs_ = (uint32_t)vmp_bin_rhs_i(in, regs); \
    VMP_RSET_I(regs[in->dst], (jint)((lhs_ | rhs_) & ~(lhs_ & rhs_))); \
    goto vmp_next_insn; \
}

#define VMP_XOR_INT_ALIAS_SALTED(label_suffix) \
VMP_##label_suffix##_LABEL: { \
    const vmp_insn_t *in = &insns[pc]; \
    uint32_t lhs_ = (uint32_t)vmp_bin_lhs_i(in, regs); \
    uint32_t rhs_ = (uint32_t)vmp_bin_rhs_i(in, regs); \
    uint32_t salt_ = ((uint32_t)in->opcode << 17) ^ 0x6D2B79F5u; \
    VMP_RSET_I(regs[in->dst], (jint)(((lhs_ ^ salt_) ^ rhs_) ^ salt_)); \
    goto vmp_next_insn; \
}

VMP_BINOP_INT_LABEL(ADD_INT, +, vmp_bin_rhs_i(in, regs))
VMP_ADD_INT_ALIAS_U32(BINOP_ALIAS1)
VMP_ADD_INT_ALIAS_COMMUTE(BINOP_ALIAS2)
VMP_ADD_INT_ALIAS_WIDE(BINOP_ALIAS3)
VMP_ADD_INT_ALIAS_SALTED(BINOP_ALIAS4)
VMP_ADD_INT_ALIAS_SPLIT16(BINOP_ALIAS5)
VMP_ADD_INT_ALIAS_NEGSUB(BINOP_ALIAS6)
VMP_ADD_INT_ALIAS_VOLATILE_ZERO(BINOP_ALIAS7)
VMP_ADD_INT_ALIAS_SPLIT_RHS(BINOP_ALIAS8)
VMP_ADD_INT_ALIAS_SALTED(BINOP_ALIAS9)
VMP_ADD_INT_ALIAS_WIDE(BINOP_ALIAS10)
VMP_ADD_INT_ALIAS_SPLIT16(BINOP_LIT_ALIAS1)
VMP_ADD_INT_ALIAS_SALTED(BINOP_LIT_ALIAS2)
VMP_ADD_INT_ALIAS_U32(BINOP_LIT_ALIAS3)
VMP_ADD_INT_ALIAS_NEGSUB(BINOP_LIT_ALIAS4)
VMP_ADD_INT_ALIAS_COMMUTE(BINOP_LIT_ALIAS5)
VMP_ADD_INT_ALIAS_VOLATILE_ZERO(BINOP_LIT_ALIAS6)
VMP_ADD_INT_ALIAS_SPLIT_RHS(BINOP_LIT_ALIAS7)
VMP_ADD_INT_ALIAS_WIDE(BINOP_LIT_ALIAS8)
VMP_SUB_INT_ALIAS_U32(SUB_ALIAS1)
VMP_SUB_INT_ALIAS_ADDNEG(SUB_ALIAS2)
VMP_SUB_INT_ALIAS_SALTED(SUB_ALIAS3)
VMP_AND_INT_ALIAS_DEMORGAN(AND_ALIAS1)
VMP_AND_INT_ALIAS_MASKED(AND_ALIAS2)
VMP_OR_INT_ALIAS_DEMORGAN(OR_ALIAS1)
VMP_OR_INT_ALIAS_SPLIT(OR_ALIAS2)
VMP_XOR_INT_ALIAS_ORAND(XOR_ALIAS1)
VMP_XOR_INT_ALIAS_SALTED(XOR_ALIAS2)
VMP_BINOP_INT_LABEL(SUB_INT, -, vmp_bin_rhs_i(in, regs))
VMP_BINOP_INT_LABEL(MUL_INT, *, vmp_bin_rhs_i(in, regs))
VMP_BINOP_INT_LABEL(AND_INT, &, vmp_bin_rhs_i(in, regs))
VMP_BINOP_INT_LABEL(OR_INT,  |, vmp_bin_rhs_i(in, regs))
VMP_BINOP_INT_LABEL(XOR_INT, ^, vmp_bin_rhs_i(in, regs))

#undef VMP_BINOP_INT_LABEL
#undef VMP_ADD_INT_ALIAS_U32
#undef VMP_ADD_INT_ALIAS_COMMUTE
#undef VMP_ADD_INT_ALIAS_WIDE
#undef VMP_ADD_INT_ALIAS_SALTED
#undef VMP_ADD_INT_ALIAS_SPLIT16
#undef VMP_ADD_INT_ALIAS_NEGSUB
#undef VMP_ADD_INT_ALIAS_VOLATILE_ZERO
#undef VMP_ADD_INT_ALIAS_SPLIT_RHS
#undef VMP_SUB_INT_ALIAS_U32
#undef VMP_SUB_INT_ALIAS_ADDNEG
#undef VMP_SUB_INT_ALIAS_SALTED
#undef VMP_AND_INT_ALIAS_DEMORGAN
#undef VMP_AND_INT_ALIAS_MASKED
#undef VMP_OR_INT_ALIAS_DEMORGAN
#undef VMP_OR_INT_ALIAS_SPLIT
#undef VMP_XOR_INT_ALIAS_ORAND
#undef VMP_XOR_INT_ALIAS_SALTED

VMP_DIV_INT_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    int32_t rhs = vmp_bin_rhs_i(in, regs);
    int32_t lhs = vmp_bin_lhs_i(in, regs);
    if (rhs == 0) { vmp_throw_arith(env, "/ by zero"); returned = 1; goto vmp_cleanup; }
    VMP_RSET_I(regs[in->dst], lhs / rhs);
    goto vmp_next_insn;
}

VMP_REM_INT_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    int32_t rhs = vmp_bin_rhs_i(in, regs);
    int32_t lhs = vmp_bin_lhs_i(in, regs);
    if (rhs == 0) { vmp_throw_arith(env, "/ by zero"); returned = 1; goto vmp_cleanup; }
    VMP_RSET_I(regs[in->dst], lhs % rhs);
    goto vmp_next_insn;
}

VMP_SHL_INT_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    int32_t rhs = vmp_bin_rhs_i(in, regs);
    int32_t lhs = vmp_bin_lhs_i(in, regs);
    VMP_RSET_I(regs[in->dst], lhs << (rhs & 0x1F));
    goto vmp_next_insn;
}

VMP_SHR_INT_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    int32_t rhs = vmp_bin_rhs_i(in, regs);
    int32_t lhs = vmp_bin_lhs_i(in, regs);
    VMP_RSET_I(regs[in->dst], lhs >> (rhs & 0x1F));
    goto vmp_next_insn;
}

VMP_USHR_INT_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    int32_t rhs = vmp_bin_rhs_i(in, regs);
    uint32_t lhs = (uint32_t) vmp_bin_lhs_i(in, regs);
    VMP_RSET_I(regs[in->dst], (jint) (lhs >> (rhs & 0x1F)));
    goto vmp_next_insn;
}

VMP_BINOP_LONG_LABEL(ADD_LONG, +)
VMP_BINOP_LONG_LABEL(SUB_LONG, -)
VMP_BINOP_LONG_LABEL(MUL_LONG, *)
VMP_BINOP_LONG_LABEL(AND_LONG, &)
VMP_BINOP_LONG_LABEL(OR_LONG, |)
VMP_BINOP_LONG_LABEL(XOR_LONG, ^)

#undef VMP_BINOP_LONG_LABEL

VMP_DIV_LONG_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    int64_t rhs = vmp_bin_rhs_j(in, regs);
    int64_t lhs = vmp_bin_lhs_j(in, regs);
    if (rhs == 0) { vmp_throw_arith(env, "/ by zero"); returned = 1; goto vmp_cleanup; }
    regs[in->dst].j = lhs / rhs;
    goto vmp_next_insn;
}

VMP_REM_LONG_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    int64_t rhs = vmp_bin_rhs_j(in, regs);
    int64_t lhs = vmp_bin_lhs_j(in, regs);
    if (rhs == 0) { vmp_throw_arith(env, "/ by zero"); returned = 1; goto vmp_cleanup; }
    regs[in->dst].j = lhs % rhs;
    goto vmp_next_insn;
}

VMP_SHL_LONG_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    int32_t rhs = vmp_bin_rhs_i(in, regs) & 0x3F;
    int64_t lhs = vmp_bin_lhs_j(in, regs);
    regs[in->dst].j = lhs << rhs;
    goto vmp_next_insn;
}

VMP_SHR_LONG_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    int32_t rhs = vmp_bin_rhs_i(in, regs) & 0x3F;
    int64_t lhs = vmp_bin_lhs_j(in, regs);
    regs[in->dst].j = lhs >> rhs;
    goto vmp_next_insn;
}

VMP_USHR_LONG_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    int32_t rhs = vmp_bin_rhs_i(in, regs) & 0x3F;
    uint64_t lhs = (uint64_t) vmp_bin_lhs_j(in, regs);
    regs[in->dst].j = (int64_t) (lhs >> rhs);
    goto vmp_next_insn;
}

#define VMP_BINOP_FLOAT_LABEL(label_suffix, op) \
VMP_##label_suffix##_LABEL: { \
    const vmp_insn_t *in = &insns[pc]; \
    jfloat rhs_ = vmp_bin_rhs_f(in, regs); \
    jfloat lhs_ = vmp_bin_lhs_f(in, regs); \
    VMP_RSET_F(regs[in->dst], lhs_ op rhs_); \
    goto vmp_next_insn; \
}

#define VMP_BINOP_DOUBLE_LABEL(label_suffix, op) \
VMP_##label_suffix##_LABEL: { \
    const vmp_insn_t *in = &insns[pc]; \
    jdouble rhs_ = vmp_bin_rhs_d(in, regs); \
    jdouble lhs_ = vmp_bin_lhs_d(in, regs); \
    regs[in->dst].d = lhs_ op rhs_; \
    goto vmp_next_insn; \
}

VMP_BINOP_FLOAT_LABEL(ADD_FLOAT, +)
VMP_BINOP_FLOAT_LABEL(SUB_FLOAT, -)
VMP_BINOP_FLOAT_LABEL(MUL_FLOAT, *)
VMP_BINOP_FLOAT_LABEL(DIV_FLOAT, /)
VMP_REM_FLOAT_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    jfloat rhs_ = vmp_bin_rhs_f(in, regs);
    jfloat lhs_ = vmp_bin_lhs_f(in, regs);
    VMP_RSET_F(regs[in->dst], fmodf(lhs_, rhs_));
    goto vmp_next_insn;
}

VMP_BINOP_DOUBLE_LABEL(ADD_DOUBLE, +)
VMP_BINOP_DOUBLE_LABEL(SUB_DOUBLE, -)
VMP_BINOP_DOUBLE_LABEL(MUL_DOUBLE, *)
VMP_BINOP_DOUBLE_LABEL(DIV_DOUBLE, /)
VMP_REM_DOUBLE_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    jdouble rhs_ = vmp_bin_rhs_d(in, regs);
    jdouble lhs_ = vmp_bin_lhs_d(in, regs);
    regs[in->dst].d = fmod(lhs_, rhs_);
    goto vmp_next_insn;
}

#undef VMP_BINOP_FLOAT_LABEL
#undef VMP_BINOP_DOUBLE_LABEL

VMP_CMP_LONG_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    int64_t a = regs[in->src1].j, b = regs[in->src2].j;
    VMP_RSET_I(regs[in->dst], (a > b) ? 1 : (a == b) ? 0 : -1);
    goto vmp_next_insn;
}
VMP_CMPG_FLOAT_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    jfloat a = regs[in->src1].f, b = regs[in->src2].f;
    VMP_RSET_I(regs[in->dst], (isnan(a) || isnan(b)) ? 1 : ((a > b) ? 1 : ((a == b) ? 0 : -1)));
    goto vmp_next_insn;
}
VMP_CMPL_FLOAT_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    jfloat a = regs[in->src1].f, b = regs[in->src2].f;
    VMP_RSET_I(regs[in->dst], (isnan(a) || isnan(b)) ? -1 : ((a > b) ? 1 : ((a == b) ? 0 : -1)));
    goto vmp_next_insn;
}
VMP_CMPG_DOUBLE_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    jdouble a = regs[in->src1].d, b = regs[in->src2].d;
    VMP_RSET_I(regs[in->dst], (isnan(a) || isnan(b)) ? 1 : ((a > b) ? 1 : ((a == b) ? 0 : -1)));
    goto vmp_next_insn;
}
VMP_CMPL_DOUBLE_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    jdouble a = regs[in->src1].d, b = regs[in->src2].d;
    VMP_RSET_I(regs[in->dst], (isnan(a) || isnan(b)) ? -1 : ((a > b) ? 1 : ((a == b) ? 0 : -1)));
    goto vmp_next_insn;
}

VMP_PACKED_SWITCH_LABEL:
VMP_SPARSE_SWITCH_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    const char *spec = vmp_pool_get((uint32_t) in->imm);
    int rel = 0;
    int sw = vmp_eval_switch_spec(spec, regs[in->dst].i, &rel);
    if (VMP_UNLIKELY(sw < 0)) {
        vmp_throw_runtime(env, "switch payload decode failed");
        returned = 1;
        goto vmp_cleanup;
    }
    if (sw > 0) {
        pc += rel;
        goto vmp_dispatch;
    }
    goto vmp_next_insn;
}

VMP_FILL_ARRAY_DATA_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    const char *spec = vmp_pool_get((uint32_t) in->imm);
    if (vmp_apply_fill_array_spec(env, regs[in->dst].l, spec) != 0) {
        if (!(*env)->ExceptionCheck(env)) {
            vmp_throw_runtime(env, "fill-array-data failed");
        }
        returned = 1;
    }
    goto vmp_next_insn;
}

VMP_FILLED_NEW_ARRAY_LABEL: {
    const vmp_insn_t *in = &insns[pc];
    if (pc + 1 >= insn_count) {
        vmp_throw_runtime(env, "filled-new-array missing args");
        returned = 1;
        goto vmp_cleanup;
    }
    const vmp_insn_t *args_in = &insns[pc + 1];
    int args_op = decoded_ops[pc + 1];
    if (args_op != VMP_INVOKE_ARGS) {
        vmp_throw_runtime(env, "filled-new-array args mismatch");
        returned = 1;
        goto vmp_cleanup;
    }
    uint8_t regs_words[256];
    int cnt = in->dst;
    if (cnt < 0 || cnt > 255 ||
        vmp_collect_invoke_regs(args_in, cnt, regs_words, 256) != 0) {
        vmp_throw_runtime(env, "filled-new-array args decode failed");
        returned = 1;
        goto vmp_cleanup;
    }
    const char *arr_desc = vmp_pool_get((uint32_t) in->imm);
    jobject arr = arr_desc ? vmp_new_array(env, arr_desc, cnt) : NULL;
    if (!arr) {
        if (!(*env)->ExceptionCheck(env)) {
            vmp_throw_runtime(env, "filled-new-array allocation failed");
        }
        returned = 1;
        goto vmp_cleanup;
    }
    for (int i = 0; i < cnt; ++i) {
        uint8_t rr = regs_words[i];
        if (rr >= VMP_MAX_REGS) continue;
        switch (arr_desc[1]) {
            case 'I': {
                jint v = regs[rr].i;
                (*env)->SetIntArrayRegion(env, (jintArray) arr, i, 1, &v);
                break;
            }
            case 'J': {
                jlong v = regs[rr].j;
                (*env)->SetLongArrayRegion(env, (jlongArray) arr, i, 1, &v);
                break;
            }
            case 'F': {
                jfloat v = regs[rr].f;
                (*env)->SetFloatArrayRegion(env, (jfloatArray) arr, i, 1, &v);
                break;
            }
            case 'D': {
                jdouble v = regs[rr].d;
                (*env)->SetDoubleArrayRegion(env, (jdoubleArray) arr, i, 1, &v);
                break;
            }
            case 'Z': {
                jboolean v = (jboolean) (regs[rr].i != 0);
                (*env)->SetBooleanArrayRegion(env, (jbooleanArray) arr, i, 1, &v);
                break;
            }
            case 'B': {
                jbyte v = (jbyte) regs[rr].i;
                (*env)->SetByteArrayRegion(env, (jbyteArray) arr, i, 1, &v);
                break;
            }
            case 'C': {
                jchar v = (jchar) regs[rr].i;
                (*env)->SetCharArrayRegion(env, (jcharArray) arr, i, 1, &v);
                break;
            }
            case 'S': {
                jshort v = (jshort) regs[rr].i;
                (*env)->SetShortArrayRegion(env, (jshortArray) arr, i, 1, &v);
                break;
            }
            default:
                (*env)->SetObjectArrayElement(env, (jobjectArray) arr, i, regs[rr].l);
                break;
        }
    }
    last.kind = VMP_LAST_OBJECT;
    last.v.l = arr;
    pc += 2;
    goto vmp_dispatch;
}

VMP_INVOKE_ARGS_LABEL:
    /* Should be consumed by invoke op. */
    goto vmp_next_insn;

VMP_CONST_WIDE_HI32_LABEL:
    /* Should be consumed by CONST_WIDE handler; skip if standalone. */
    goto vmp_next_insn;

    /* ---- Dispatch loop tail ---- */

vmp_next_insn:
    pc++;
vmp_dispatch:
    if (VMP_UNLIKELY(--step_budget <= 0)) {
        vmp_throw_runtime(env, "VMP execution step budget exceeded");
        goto vmp_cleanup;
    }
    if (VMP_UNLIKELY(pc < 0 || pc >= insn_count)) goto vmp_cleanup;
    goto *dispatch_table[decoded_ops[pc]];

vmp_cleanup: ;

#else  /* portable fallback: switch-case dispatch */
    while (pc >= 0 && pc < insn_count && !returned) {
        if (--step_budget <= 0) {
            vmp_throw_runtime(env, "VMP execution step budget exceeded");
            break;
        }
        const vmp_insn_t *in = &insns[pc];
        int rop = _active_ctx->opcode_table[in->opcode];
        switch (rop) {
            case VMP_NOP:
                break;

            case VMP_MOVE:
            case VMP_MOVE_WIDE:
            case VMP_MOVE_OBJECT:
                regs[in->dst] = regs[in->src1];
                break;

            case VMP_MOVE_RESULT:
                switch (last.kind) {
                    case VMP_LAST_INT: VMP_RSET_I(regs[in->dst], last.v.i); break;
                    case VMP_LAST_LONG: VMP_RSET_I(regs[in->dst], (jint) last.v.j); break;
                    case VMP_LAST_FLOAT: VMP_RSET_F(regs[in->dst], last.v.f); break;
                    case VMP_LAST_DOUBLE: VMP_RSET_I(regs[in->dst], (jint) last.v.d); break;
                    case VMP_LAST_OBJECT: regs[in->dst].l = last.v.l; break;
                    default: VMP_RSET_I(regs[in->dst], 0); break;
                }
                last.kind = VMP_LAST_VOID;
                break;

            case VMP_MOVE_RESULT_WIDE:
                if (last.kind == VMP_LAST_LONG) {
                    regs[in->dst].j = last.v.j;
                } else if (last.kind == VMP_LAST_DOUBLE) {
                    regs[in->dst].d = last.v.d;
                } else {
                    regs[in->dst].j = 0;
                }
                if (in->dst + 1 < VMP_MAX_REGS) regs[in->dst + 1] = regs[in->dst];
                last.kind = VMP_LAST_VOID;
                break;

            case VMP_MOVE_RESULT_OBJECT:
                regs[in->dst].l = (last.kind == VMP_LAST_OBJECT) ? last.v.l : NULL;
                last.kind = VMP_LAST_VOID;
                break;

            case VMP_MOVE_EXCEPTION:
                if (caught_exception) {
                    regs[in->dst].l = caught_exception;
                    caught_exception = NULL;
                } else if ((*env)->ExceptionCheck(env)) {
                    jobject ex = (*env)->ExceptionOccurred(env);
                    (*env)->ExceptionClear(env);
                    regs[in->dst].l = ex;
                } else {
                    regs[in->dst].l = NULL;
                }
                break;

            case VMP_RETURN_VOID:
                return_op = VMP_RETURN_VOID;
                returned = 1;
                break;
            case VMP_RETURN:
                ret_reg = regs[in->dst];
                return_op = VMP_RETURN;
                returned = 1;
                break;
            case VMP_RETURN_WIDE:
                ret_reg = regs[in->dst];
                return_op = VMP_RETURN_WIDE;
                returned = 1;
                break;
            case VMP_RETURN_OBJECT:
                ret_reg = regs[in->dst];
                return_op = VMP_RETURN_OBJECT;
                returned = 1;
                break;

            case VMP_CONST:
                VMP_RSET_I(regs[in->dst], in->imm);
                break;

            case VMP_CONST_WIDE: {
                int64_t v = (int64_t) in->imm;
                if (pc + 1 < insn_count) {
                    int next_op = _active_ctx->opcode_table[insns[pc + 1].opcode];
                    if (next_op == VMP_CONST_WIDE_HI32) {
                        uint64_t lo = (uint32_t) in->imm;
                        uint64_t hi = (uint32_t) insns[pc + 1].imm;
                        v = (int64_t) (lo | (hi << 32));
                        regs[in->dst].j = v;
                        if (in->dst + 1 < VMP_MAX_REGS) regs[in->dst + 1] = regs[in->dst];
                        pc += 2;
                        continue;
                    }
                }
                regs[in->dst].j = v;
                if (in->dst + 1 < VMP_MAX_REGS) regs[in->dst + 1] = regs[in->dst];
                break;
            }

            case VMP_CONST_STRING: {
                const char *s = vmp_pool_get((uint32_t) in->imm);
                regs[in->dst].l = s ? (*env)->NewStringUTF(env, s) : NULL;
                break;
            }

            case VMP_CONST_CLASS: {
                const char *desc = vmp_pool_get((uint32_t) in->imm);
                regs[in->dst].l = desc ? vmp_resolve_class(env, desc) : NULL;
                break;
            }

            case VMP_MONITOR_ENTER:
                if ((*env)->MonitorEnter(env, regs[in->dst].l) != JNI_OK) {
                    vmp_throw_runtime(env, "monitor-enter failed");
                }
                break;
            case VMP_MONITOR_EXIT:
                if ((*env)->MonitorExit(env, regs[in->dst].l) != JNI_OK) {
                    vmp_throw_runtime(env, "monitor-exit failed");
                }
                break;

            case VMP_CHECK_CAST: {
                const char *desc = vmp_pool_get((uint32_t) in->imm);
                jobject obj = regs[in->dst].l;
                if (obj != NULL && desc != NULL) {
                    jclass cls = vmp_resolve_class(env, desc);
                    if (!cls) break;
                    if (!(*env)->IsInstanceOf(env, obj, cls)) {
                        (*env)->DeleteLocalRef(env, cls);
                        vmp_throw(env, "java/lang/ClassCastException", "check-cast failed");
                        break;
                    }
                    (*env)->DeleteLocalRef(env, cls);
                }
                break;
            }

            case VMP_INSTANCE_OF: {
                const char *desc = vmp_pool_get((uint32_t) in->imm);
                jobject obj = regs[in->src1].l;
                jclass cls = desc ? vmp_resolve_class(env, desc) : NULL;
                VMP_RSET_I(regs[in->dst], (obj && cls && (*env)->IsInstanceOf(env, obj, cls)) ? 1 : 0);
                if (cls) (*env)->DeleteLocalRef(env, cls);
                break;
            }

            case VMP_NEW_INSTANCE: {
                const char *desc = vmp_pool_get((uint32_t) in->imm);
                jclass cls = desc ? vmp_resolve_class(env, desc) : NULL;
                regs[in->dst].l = cls ? (*env)->AllocObject(env, cls) : NULL;
                if (cls) (*env)->DeleteLocalRef(env, cls);
                break;
            }

            case VMP_NEW_ARRAY: {
                const char *desc = vmp_pool_get((uint32_t) in->imm);
                regs[in->dst].l = desc ? vmp_new_array(env, desc, regs[in->src1].i) : NULL;
                break;
            }

            case VMP_ARRAY_LENGTH:
                VMP_RSET_I(regs[in->dst], regs[in->src1].l ? (*env)->GetArrayLength(env, (jarray) regs[in->src1].l) : 0);
                break;

            case VMP_THROW:
                if (regs[in->dst].l) {
                    (*env)->Throw(env, (jthrowable) regs[in->dst].l);
                } else {
                    vmp_throw_runtime(env, "throw null");
                }
                returned = 1;
                return_op = VMP_RETURN_VOID;
                break;

            case VMP_GOTO:
                pc += in->imm;
                continue;

            case VMP_IF_EQ:
                if (vmp_branch_cond_eq(regs[in->dst], regs[in->src1])) {
                    pc += in->imm;
                    continue;
                }
                break;
            case VMP_IF_NE:
                if (vmp_branch_cond_ne(regs[in->dst], regs[in->src1])) {
                    pc += in->imm;
                    continue;
                }
                break;
            case VMP_IF_LT:
                if (regs[in->dst].i < regs[in->src1].i) {
                    pc += in->imm;
                    continue;
                }
                break;
            case VMP_IF_GE:
                if (regs[in->dst].i >= regs[in->src1].i) {
                    pc += in->imm;
                    continue;
                }
                break;
            case VMP_IF_GT:
                if (regs[in->dst].i > regs[in->src1].i) {
                    pc += in->imm;
                    continue;
                }
                break;
            case VMP_IF_LE:
                if (regs[in->dst].i <= regs[in->src1].i) {
                    pc += in->imm;
                    continue;
                }
                break;

            case VMP_IF_EQZ:
                if (regs[in->dst].j == 0) { pc += in->imm; continue; }
                break;
            case VMP_IF_NEZ:
                if (regs[in->dst].j != 0) { pc += in->imm; continue; }
                break;
            case VMP_IF_LTZ:
                if (regs[in->dst].i < 0) { pc += in->imm; continue; }
                break;
            case VMP_IF_GEZ:
                if (regs[in->dst].i >= 0) { pc += in->imm; continue; }
                break;
            case VMP_IF_GTZ:
                if (regs[in->dst].i > 0) { pc += in->imm; continue; }
                break;
            case VMP_IF_LEZ:
                if (regs[in->dst].i <= 0) { pc += in->imm; continue; }
                break;

            case VMP_AGET:
            case VMP_AGET_WIDE:
            case VMP_AGET_OBJECT:
            case VMP_AGET_BOOLEAN:
            case VMP_AGET_BYTE:
            case VMP_AGET_CHAR:
            case VMP_AGET_SHORT:
                vmp_array_get(env, vmp_kind_from_aget_op(rop), regs, in->dst, in->src1, in->src2);
                break;

            case VMP_APUT:
            case VMP_APUT_WIDE:
            case VMP_APUT_OBJECT:
            case VMP_APUT_BOOLEAN:
            case VMP_APUT_BYTE:
            case VMP_APUT_CHAR:
            case VMP_APUT_SHORT:
                vmp_array_put(env, vmp_kind_from_aput_op(rop), regs, in->dst, in->src1, in->src2);
                break;

            case VMP_IGET:
            case VMP_IGET_WIDE:
            case VMP_IGET_OBJECT:
            case VMP_IGET_BOOLEAN:
            case VMP_IGET_BYTE:
            case VMP_IGET_CHAR:
            case VMP_IGET_SHORT: {
                const char *ref = vmp_pool_get((uint32_t) in->imm);
                if (ref) (void) vmp_field_get(env, vmp_kind_from_iget_op(rop), 0, regs, in->dst, in->src1, ref);
                break;
            }

            case VMP_IPUT:
            case VMP_IPUT_WIDE:
            case VMP_IPUT_OBJECT:
            case VMP_IPUT_BOOLEAN:
            case VMP_IPUT_BYTE:
            case VMP_IPUT_CHAR:
            case VMP_IPUT_SHORT: {
                const char *ref = vmp_pool_get((uint32_t) in->imm);
                if (ref) (void) vmp_field_put(env, vmp_kind_from_iput_op(rop), 0, regs, in->dst, in->src1, ref);
                break;
            }

            case VMP_SGET:
            case VMP_SGET_WIDE:
            case VMP_SGET_OBJECT:
            case VMP_SGET_BOOLEAN:
            case VMP_SGET_BYTE:
            case VMP_SGET_CHAR:
            case VMP_SGET_SHORT: {
                const char *ref = vmp_pool_get((uint32_t) in->imm);
                if (ref) (void) vmp_field_get(env, vmp_kind_from_sget_op(rop), 1, regs, in->dst, 0, ref);
                break;
            }

            case VMP_SPUT:
            case VMP_SPUT_WIDE:
            case VMP_SPUT_OBJECT:
            case VMP_SPUT_BOOLEAN:
            case VMP_SPUT_BYTE:
            case VMP_SPUT_CHAR:
            case VMP_SPUT_SHORT: {
                const char *ref = vmp_pool_get((uint32_t) in->imm);
                if (ref) (void) vmp_field_put(env, vmp_kind_from_sput_op(rop), 1, regs, in->dst, 0, ref);
                break;
            }

            case VMP_INVOKE_VIRTUAL:
            case VMP_INVOKE_SUPER:
            case VMP_INVOKE_DIRECT:
            case VMP_INVOKE_STATIC:
            case VMP_INVOKE_INTERFACE: {
                if (pc + 1 >= insn_count) {
                    vmp_throw_runtime(env, "invoke missing INVOKE_ARGS");
                    returned = 1;
                    break;
                }
                const vmp_insn_t *args_in = &insns[pc + 1];
                int args_op = _active_ctx->opcode_table[args_in->opcode];
                if (args_op != VMP_INVOKE_ARGS) {
                    vmp_throw_runtime(env, "invoke arg format mismatch");
                    returned = 1;
                    break;
                }
                uint8_t regs_words[256];
                int arg_words = in->dst;
                if (arg_words < 0 || arg_words > 255) {
                    vmp_throw_runtime(env, "invoke arg count invalid");
                    returned = 1;
                    break;
                }
                if (vmp_collect_invoke_regs(args_in, arg_words, regs_words, 256) != 0) {
                    vmp_throw_runtime(env, "invoke arg decode failed");
                    returned = 1;
                    break;
                }
                const char *ref = vmp_pool_get((uint32_t) in->imm);
                if (!ref || vmp_invoke_ref(env, rop, ref, regs_words, arg_words, regs, &last) != 0) {
                    if (!(*env)->ExceptionCheck(env)) {
                        vmp_throw_runtime(env, "invoke failed");
                    }
                    returned = 1;
                    break;
                }
                pc += 2;
                continue;
            }

            case VMP_INVOKE_CUSTOM: {
                if (pc + 1 >= insn_count) {
                    vmp_throw_runtime(env, "invoke-custom missing INVOKE_ARGS");
                    returned = 1;
                    break;
                }
                const vmp_insn_t *args_in = &insns[pc + 1];
                int args_op = _active_ctx->opcode_table[args_in->opcode];
                if (args_op != VMP_INVOKE_ARGS) {
                    vmp_throw_runtime(env, "invoke-custom arg format mismatch");
                    returned = 1;
                    break;
                }
                uint8_t regs_words[256];
                int arg_words = in->dst;
                if (arg_words < 0 || arg_words > 255) {
                    vmp_throw_runtime(env, "invoke-custom arg count invalid");
                    returned = 1;
                    break;
                }
                if (vmp_collect_invoke_regs(args_in, arg_words, regs_words, 256) != 0) {
                    vmp_throw_runtime(env, "invoke-custom arg decode failed");
                    returned = 1;
                    break;
                }
                const char *cs_ref = vmp_pool_get((uint32_t) in->imm);
                if (!cs_ref || strncmp(cs_ref, "@cs:", 4) != 0) {
                    vmp_throw_runtime(env, "invoke-custom bad ref");
                    returned = 1;
                    break;
                }
                /* Parse: @cs:<kind>|<target_ref>|<iface_name>
                 * For lambda targets (kind 4=static, 5=virtual), invoke target directly. */
                const char *payload = cs_ref + 4;
                const char *pipe1 = strchr(payload, '|');
                if (!pipe1) {
                    vmp_throw_runtime(env, "invoke-custom malformed ref");
                    returned = 1;
                    break;
                }
                const char *target_ref = pipe1 + 1;
                const char *pipe2 = strchr(target_ref, '|');
                /* Isolate target_ref (may need null-term) */
                char target_buf[512];
                int tlen = pipe2 ? (int)(pipe2 - target_ref) : (int)strlen(target_ref);
                if (tlen >= (int)sizeof(target_buf)) tlen = (int)sizeof(target_buf) - 1;
                memcpy(target_buf, target_ref, tlen);
                target_buf[tlen] = '\0';
                /* Invoke the target method as static — this works for LambdaMetafactory
                 * targets where the impl is a synthetic static method. */
                if (vmp_invoke_ref(env, VMP_INVOKE_STATIC, target_buf,
                                   regs_words, arg_words, regs, &last) != 0) {
                    if (!(*env)->ExceptionCheck(env)) {
                        vmp_throw_runtime(env, "invoke-custom target call failed");
                    }
                    returned = 1;
                    break;
                }
                pc += 2;
                continue;
            }

            case VMP_INVOKE_POLYMORPHIC: {
                /* invoke-polymorphic: same as a regular invoke on MethodHandle.invoke() */
                if (pc + 1 >= insn_count) {
                    vmp_throw_runtime(env, "invoke-polymorphic missing INVOKE_ARGS");
                    returned = 1;
                    break;
                }
                const vmp_insn_t *args_in = &insns[pc + 1];
                int args_op = _active_ctx->opcode_table[args_in->opcode];
                if (args_op != VMP_INVOKE_ARGS) {
                    vmp_throw_runtime(env, "invoke-polymorphic arg format mismatch");
                    returned = 1;
                    break;
                }
                uint8_t regs_words[256];
                int arg_words = in->dst;
                if (arg_words < 0 || arg_words > 255) {
                    vmp_throw_runtime(env, "invoke-polymorphic arg count invalid");
                    returned = 1;
                    break;
                }
                if (vmp_collect_invoke_regs(args_in, arg_words, regs_words, 256) != 0) {
                    vmp_throw_runtime(env, "invoke-polymorphic arg decode failed");
                    returned = 1;
                    break;
                }
                const char *ref = vmp_pool_get((uint32_t) in->imm);
                /* Delegate to vmp_invoke_ref as a virtual call on the MethodHandle */
                if (!ref || vmp_invoke_ref(env, VMP_INVOKE_VIRTUAL, ref,
                                           regs_words, arg_words, regs, &last) != 0) {
                    if (!(*env)->ExceptionCheck(env)) {
                        vmp_throw_runtime(env, "invoke-polymorphic failed");
                    }
                    returned = 1;
                    break;
                }
                pc += 2;
                continue;
            }

            case VMP_NEG_INT: VMP_RSET_I(regs[in->dst], -regs[in->src1].i); break;
            case VMP_NOT_INT: VMP_RSET_I(regs[in->dst], ~regs[in->src1].i); break;
            case VMP_NEG_LONG: regs[in->dst].j = -regs[in->src1].j; break;
            case VMP_NOT_LONG: regs[in->dst].j = ~regs[in->src1].j; break;
            case VMP_NEG_FLOAT: VMP_RSET_F(regs[in->dst], -regs[in->src1].f); break;
            case VMP_NEG_DOUBLE: regs[in->dst].d = -regs[in->src1].d; break;

            case VMP_INT_TO_LONG: regs[in->dst].j = (jlong) regs[in->src1].i; break;
            case VMP_INT_TO_FLOAT: VMP_RSET_F(regs[in->dst], (jfloat) regs[in->src1].i); break;
            case VMP_INT_TO_DOUBLE: regs[in->dst].d = (jdouble) regs[in->src1].i; break;
            case VMP_LONG_TO_INT: VMP_RSET_I(regs[in->dst], (jint) regs[in->src1].j); break;
            case VMP_LONG_TO_FLOAT: VMP_RSET_F(regs[in->dst], (jfloat) regs[in->src1].j); break;
            case VMP_LONG_TO_DOUBLE: regs[in->dst].d = (jdouble) regs[in->src1].j; break;
            case VMP_FLOAT_TO_INT: VMP_RSET_I(regs[in->dst], (jint) regs[in->src1].f); break;
            case VMP_FLOAT_TO_LONG: regs[in->dst].j = (jlong) regs[in->src1].f; break;
            case VMP_FLOAT_TO_DOUBLE: regs[in->dst].d = (jdouble) regs[in->src1].f; break;
            case VMP_DOUBLE_TO_INT: VMP_RSET_I(regs[in->dst], (jint) regs[in->src1].d); break;
            case VMP_DOUBLE_TO_LONG: regs[in->dst].j = (jlong) regs[in->src1].d; break;
            case VMP_DOUBLE_TO_FLOAT: VMP_RSET_F(regs[in->dst], (jfloat) regs[in->src1].d); break;
            case VMP_INT_TO_BYTE: VMP_RSET_I(regs[in->dst], (jbyte) regs[in->src1].i); break;
            case VMP_INT_TO_CHAR: VMP_RSET_I(regs[in->dst], (jchar) regs[in->src1].i); break;
            case VMP_INT_TO_SHORT: VMP_RSET_I(regs[in->dst], (jshort) regs[in->src1].i); break;

            case VMP_ADD_INT:
            case VMP_BINOP_ALIAS1:
            case VMP_BINOP_ALIAS2:
            case VMP_BINOP_ALIAS3:
            case VMP_BINOP_ALIAS4:
            case VMP_BINOP_ALIAS5:
            case VMP_BINOP_ALIAS6:
            case VMP_BINOP_ALIAS7:
            case VMP_BINOP_ALIAS8:
            case VMP_BINOP_ALIAS9:
            case VMP_BINOP_ALIAS10:
            case VMP_BINOP_LIT_ALIAS1:
            case VMP_BINOP_LIT_ALIAS2:
            case VMP_BINOP_LIT_ALIAS3:
            case VMP_BINOP_LIT_ALIAS4:
            case VMP_BINOP_LIT_ALIAS5:
            case VMP_BINOP_LIT_ALIAS6:
            case VMP_BINOP_LIT_ALIAS7:
            case VMP_BINOP_LIT_ALIAS8: {
                int32_t rhs = vmp_bin_rhs_i(in, regs);
                int32_t lhs = vmp_bin_lhs_i(in, regs);
                VMP_RSET_I(regs[in->dst], lhs + rhs);
                break;
            }
            case VMP_SUB_INT:
            case VMP_UNOP_ALIAS1:
            case VMP_UNOP_ALIAS2:
            case VMP_UNOP_ALIAS3: {
                int32_t rhs = vmp_bin_rhs_i(in, regs);
                int32_t lhs = vmp_bin_lhs_i(in, regs);
                VMP_RSET_I(regs[in->dst], lhs - rhs);
                break;
            }
            case VMP_MUL_INT: {
                int32_t rhs = vmp_bin_rhs_i(in, regs);
                int32_t lhs = vmp_bin_lhs_i(in, regs);
                VMP_RSET_I(regs[in->dst], lhs * rhs);
                break;
            }
            case VMP_DIV_INT: {
                int32_t rhs = vmp_bin_rhs_i(in, regs);
                int32_t lhs = vmp_bin_lhs_i(in, regs);
                if (rhs == 0) {
                    vmp_throw_arith(env, "/ by zero");
                    returned = 1;
                    break;
                }
                VMP_RSET_I(regs[in->dst], lhs / rhs);
                break;
            }
            case VMP_REM_INT: {
                int32_t rhs = vmp_bin_rhs_i(in, regs);
                int32_t lhs = vmp_bin_lhs_i(in, regs);
                if (rhs == 0) {
                    vmp_throw_arith(env, "/ by zero");
                    returned = 1;
                    break;
                }
                VMP_RSET_I(regs[in->dst], lhs % rhs);
                break;
            }
            case VMP_AND_INT:
            case VMP_UNOP_ALIAS4:
            case VMP_UNOP_ALIAS5: {
                int32_t rhs = vmp_bin_rhs_i(in, regs);
                int32_t lhs = vmp_bin_lhs_i(in, regs);
                VMP_RSET_I(regs[in->dst], lhs & rhs);
                break;
            }
            case VMP_OR_INT:
            case VMP_IF_ALIAS1:
            case VMP_IF_ALIAS2: {
                int32_t rhs = vmp_bin_rhs_i(in, regs);
                int32_t lhs = vmp_bin_lhs_i(in, regs);
                VMP_RSET_I(regs[in->dst], lhs | rhs);
                break;
            }
            case VMP_XOR_INT:
            case VMP_IF_ALIAS3:
            case VMP_IF_ALIAS4: {
                int32_t rhs = vmp_bin_rhs_i(in, regs);
                int32_t lhs = vmp_bin_lhs_i(in, regs);
                VMP_RSET_I(regs[in->dst], lhs ^ rhs);
                break;
            }
            case VMP_SHL_INT: {
                int32_t rhs = vmp_bin_rhs_i(in, regs);
                int32_t lhs = vmp_bin_lhs_i(in, regs);
                VMP_RSET_I(regs[in->dst], lhs << (rhs & 0x1F));
                break;
            }
            case VMP_SHR_INT: {
                int32_t rhs = vmp_bin_rhs_i(in, regs);
                int32_t lhs = vmp_bin_lhs_i(in, regs);
                VMP_RSET_I(regs[in->dst], lhs >> (rhs & 0x1F));
                break;
            }
            case VMP_USHR_INT: {
                int32_t rhs = vmp_bin_rhs_i(in, regs);
                uint32_t lhs = (uint32_t) vmp_bin_lhs_i(in, regs);
                VMP_RSET_I(regs[in->dst], (jint) (lhs >> (rhs & 0x1F)));
                break;
            }

            case VMP_ADD_LONG: {
                int64_t rhs = vmp_bin_rhs_j(in, regs);
                int64_t lhs = vmp_bin_lhs_j(in, regs);
                regs[in->dst].j = lhs + rhs;
                break;
            }
            case VMP_SUB_LONG: {
                int64_t rhs = vmp_bin_rhs_j(in, regs);
                int64_t lhs = vmp_bin_lhs_j(in, regs);
                regs[in->dst].j = lhs - rhs;
                break;
            }
            case VMP_MUL_LONG: {
                int64_t rhs = vmp_bin_rhs_j(in, regs);
                int64_t lhs = vmp_bin_lhs_j(in, regs);
                regs[in->dst].j = lhs * rhs;
                break;
            }
            case VMP_DIV_LONG: {
                int64_t rhs = vmp_bin_rhs_j(in, regs);
                int64_t lhs = vmp_bin_lhs_j(in, regs);
                if (rhs == 0) {
                    vmp_throw_arith(env, "/ by zero");
                    returned = 1;
                    break;
                }
                regs[in->dst].j = lhs / rhs;
                break;
            }
            case VMP_REM_LONG: {
                int64_t rhs = vmp_bin_rhs_j(in, regs);
                int64_t lhs = vmp_bin_lhs_j(in, regs);
                if (rhs == 0) {
                    vmp_throw_arith(env, "/ by zero");
                    returned = 1;
                    break;
                }
                regs[in->dst].j = lhs % rhs;
                break;
            }
            case VMP_AND_LONG: {
                int64_t rhs = vmp_bin_rhs_j(in, regs);
                int64_t lhs = vmp_bin_lhs_j(in, regs);
                regs[in->dst].j = lhs & rhs;
                break;
            }
            case VMP_OR_LONG: {
                int64_t rhs = vmp_bin_rhs_j(in, regs);
                int64_t lhs = vmp_bin_lhs_j(in, regs);
                regs[in->dst].j = lhs | rhs;
                break;
            }
            case VMP_XOR_LONG: {
                int64_t rhs = vmp_bin_rhs_j(in, regs);
                int64_t lhs = vmp_bin_lhs_j(in, regs);
                regs[in->dst].j = lhs ^ rhs;
                break;
            }
            case VMP_SHL_LONG: {
                int32_t rhs = vmp_bin_rhs_i(in, regs);
                int64_t lhs = vmp_bin_lhs_j(in, regs);
                regs[in->dst].j = lhs << (rhs & 0x3F);
                break;
            }
            case VMP_SHR_LONG: {
                int32_t rhs = vmp_bin_rhs_i(in, regs);
                int64_t lhs = vmp_bin_lhs_j(in, regs);
                regs[in->dst].j = lhs >> (rhs & 0x3F);
                break;
            }
            case VMP_USHR_LONG: {
                int32_t rhs = vmp_bin_rhs_i(in, regs);
                uint64_t lhs = (uint64_t) vmp_bin_lhs_j(in, regs);
                regs[in->dst].j = (jlong) (lhs >> (rhs & 0x3F));
                break;
            }

            case VMP_ADD_FLOAT: VMP_RSET_F(regs[in->dst], vmp_bin_lhs_f(in, regs) + vmp_bin_rhs_f(in, regs)); break;
            case VMP_SUB_FLOAT: VMP_RSET_F(regs[in->dst], vmp_bin_lhs_f(in, regs) - vmp_bin_rhs_f(in, regs)); break;
            case VMP_MUL_FLOAT: VMP_RSET_F(regs[in->dst], vmp_bin_lhs_f(in, regs) * vmp_bin_rhs_f(in, regs)); break;
            case VMP_DIV_FLOAT: VMP_RSET_F(regs[in->dst], vmp_bin_lhs_f(in, regs) / vmp_bin_rhs_f(in, regs)); break;
            case VMP_REM_FLOAT: VMP_RSET_F(regs[in->dst], fmodf(vmp_bin_lhs_f(in, regs), vmp_bin_rhs_f(in, regs))); break;

            case VMP_ADD_DOUBLE: regs[in->dst].d = vmp_bin_lhs_d(in, regs) + vmp_bin_rhs_d(in, regs); break;
            case VMP_SUB_DOUBLE: regs[in->dst].d = vmp_bin_lhs_d(in, regs) - vmp_bin_rhs_d(in, regs); break;
            case VMP_MUL_DOUBLE: regs[in->dst].d = vmp_bin_lhs_d(in, regs) * vmp_bin_rhs_d(in, regs); break;
            case VMP_DIV_DOUBLE: regs[in->dst].d = vmp_bin_lhs_d(in, regs) / vmp_bin_rhs_d(in, regs); break;
            case VMP_REM_DOUBLE: regs[in->dst].d = fmod(vmp_bin_lhs_d(in, regs), vmp_bin_rhs_d(in, regs)); break;

            case VMP_CMP_LONG: {
                jlong a = regs[in->src1].j, b = regs[in->src2].j;
                VMP_RSET_I(regs[in->dst], (a > b) ? 1 : ((a == b) ? 0 : -1));
                break;
            }
            case VMP_CMPG_FLOAT: {
                jfloat a = regs[in->src1].f, b = regs[in->src2].f;
                VMP_RSET_I(regs[in->dst], (isnan(a) || isnan(b)) ? 1 : ((a > b) ? 1 : ((a == b) ? 0 : -1)));
                break;
            }
            case VMP_CMPL_FLOAT: {
                jfloat a = regs[in->src1].f, b = regs[in->src2].f;
                VMP_RSET_I(regs[in->dst], (isnan(a) || isnan(b)) ? -1 : ((a > b) ? 1 : ((a == b) ? 0 : -1)));
                break;
            }
            case VMP_CMPG_DOUBLE: {
                jdouble a = regs[in->src1].d, b = regs[in->src2].d;
                VMP_RSET_I(regs[in->dst], (isnan(a) || isnan(b)) ? 1 : ((a > b) ? 1 : ((a == b) ? 0 : -1)));
                break;
            }
            case VMP_CMPL_DOUBLE: {
                jdouble a = regs[in->src1].d, b = regs[in->src2].d;
                VMP_RSET_I(regs[in->dst], (isnan(a) || isnan(b)) ? -1 : ((a > b) ? 1 : ((a == b) ? 0 : -1)));
                break;
            }

            case VMP_PACKED_SWITCH:
            case VMP_SPARSE_SWITCH: {
                const char *spec = vmp_pool_get((uint32_t) in->imm);
                int rel = 0;
                int sw = vmp_eval_switch_spec(spec, regs[in->dst].i, &rel);
                if (sw < 0) {
                    vmp_throw_runtime(env, "switch payload decode failed");
                    returned = 1;
                    break;
                }
                if (sw > 0) {
                    pc += rel;
                    continue;
                }
                break;
            }

            case VMP_FILL_ARRAY_DATA: {
                const char *spec = vmp_pool_get((uint32_t) in->imm);
                if (vmp_apply_fill_array_spec(env, regs[in->dst].l, spec) != 0) {
                    if (!(*env)->ExceptionCheck(env)) {
                        vmp_throw_runtime(env, "fill-array-data failed");
                    }
                    returned = 1;
                }
                break;
            }

            case VMP_FILLED_NEW_ARRAY: {
                if (pc + 1 >= insn_count) {
                    vmp_throw_runtime(env, "filled-new-array missing args");
                    returned = 1;
                    break;
                }
                const vmp_insn_t *args_in = &insns[pc + 1];
                int args_op = _active_ctx->opcode_table[args_in->opcode];
                if (args_op != VMP_INVOKE_ARGS) {
                    vmp_throw_runtime(env, "filled-new-array args mismatch");
                    returned = 1;
                    break;
                }
                uint8_t regs_words[256];
                int cnt = in->dst;
                if (cnt < 0 || cnt > 255 ||
                    vmp_collect_invoke_regs(args_in, cnt, regs_words, 256) != 0) {
                    vmp_throw_runtime(env, "filled-new-array args decode failed");
                    returned = 1;
                    break;
                }
                const char *arr_desc = vmp_pool_get((uint32_t) in->imm);
                jobject arr = arr_desc ? vmp_new_array(env, arr_desc, cnt) : NULL;
                if (!arr) {
                    if (!(*env)->ExceptionCheck(env)) {
                        vmp_throw_runtime(env, "filled-new-array allocation failed");
                    }
                    returned = 1;
                    break;
                }
                for (int i = 0; i < cnt; ++i) {
                    uint8_t rr = regs_words[i];
                    if (rr >= VMP_MAX_REGS) continue;
                    switch (arr_desc[1]) {
                        case 'I': {
                            jint v = regs[rr].i;
                            (*env)->SetIntArrayRegion(env, (jintArray) arr, i, 1, &v);
                            break;
                        }
                        case 'J': {
                            jlong v = regs[rr].j;
                            (*env)->SetLongArrayRegion(env, (jlongArray) arr, i, 1, &v);
                            break;
                        }
                        case 'F': {
                            jfloat v = regs[rr].f;
                            (*env)->SetFloatArrayRegion(env, (jfloatArray) arr, i, 1, &v);
                            break;
                        }
                        case 'D': {
                            jdouble v = regs[rr].d;
                            (*env)->SetDoubleArrayRegion(env, (jdoubleArray) arr, i, 1, &v);
                            break;
                        }
                        case 'Z': {
                            jboolean v = (jboolean) (regs[rr].i != 0);
                            (*env)->SetBooleanArrayRegion(env, (jbooleanArray) arr, i, 1, &v);
                            break;
                        }
                        case 'B': {
                            jbyte v = (jbyte) regs[rr].i;
                            (*env)->SetByteArrayRegion(env, (jbyteArray) arr, i, 1, &v);
                            break;
                        }
                        case 'C': {
                            jchar v = (jchar) regs[rr].i;
                            (*env)->SetCharArrayRegion(env, (jcharArray) arr, i, 1, &v);
                            break;
                        }
                        case 'S': {
                            jshort v = (jshort) regs[rr].i;
                            (*env)->SetShortArrayRegion(env, (jshortArray) arr, i, 1, &v);
                            break;
                        }
                        default:
                            (*env)->SetObjectArrayElement(env, (jobjectArray) arr, i, regs[rr].l);
                            break;
                    }
                }
                last.kind = VMP_LAST_OBJECT;
                last.v.l = arr;
                pc += 2;
                continue;
            }

            case VMP_INVOKE_ARGS:
                /* Should be consumed by invoke op. */
                break;

            case VMP_CONST_WIDE_HI32:
                /* Should be consumed by CONST_WIDE handler; skip if standalone. */
                break;

            default:
                vmp_throw_runtime(env, "VMP op not implemented");
                returned = 1;
                break;
        }

        if (VMP_UNLIKELY(returned)) break;
        if (VMP_UNLIKELY((*env)->ExceptionCheck(env))) {
            int handled = 0;
            if (method_tries && method_tries->try_count > 0) {
                jthrowable ex = (*env)->ExceptionOccurred(env);
                (*env)->ExceptionClear(env);
                for (uint16_t t = 0; t < method_tries->try_count && !handled; ++t) {
                    const vmp_try_block_t *tb = &method_tries->tries[t];
                    if (pc < (int)tb->start_pc || pc >= (int)tb->end_pc) continue;
                    /* Check typed handlers */
                    for (uint16_t h = 0; h < tb->handler_count; ++h) {
                        int32_t tidx = tb->handlers[h].type_str_idx;
                        if (tidx >= 0 && (uint32_t)tidx < _active_ctx->string_count) {
                            jclass ecls = vmp_resolve_class(env, _active_ctx->strings[tidx]);
                            if (ecls && (*env)->IsInstanceOf(env, (jobject)ex, ecls)) {
                                if (caught_exception) (*env)->DeleteLocalRef(env, caught_exception);
                                caught_exception = (jobject)ex;
                                pc = tb->handlers[h].handler_pc;
                                handled = 1;
                                break;
                            }
                        }
                    }
                    /* Check catch-all */
                    if (!handled && tb->catch_all_pc >= 0) {
                        if (caught_exception) (*env)->DeleteLocalRef(env, caught_exception);
                        caught_exception = (jobject)ex;
                        pc = tb->catch_all_pc;
                        handled = 1;
                    }
                }
                if (!handled) {
                    (*env)->Throw(env, ex);
                    (*env)->DeleteLocalRef(env, (jobject)ex);
                }
            }
            if (!handled) break;
            continue; /* Jump to handler, don't increment pc */
        }
        pc++;
    }
#endif

    if (caught_exception) {
        (*env)->DeleteLocalRef(env, caught_exception);
        caught_exception = NULL;
    }

    if ((*env)->ExceptionCheck(env)) {
        (*env)->PopLocalFrame(env, NULL);
        return NULL;
    }

    if (!returned) {
        /* Fallthrough: treat as void. */
        (*env)->PopLocalFrame(env, NULL);
        return NULL;
    }

    if (return_op == VMP_RETURN_VOID) {
        (*env)->PopLocalFrame(env, NULL);
        return NULL;
    }

    if (return_op == VMP_RETURN_OBJECT) {
        /* PopLocalFrame keeps exactly one ref alive across the frame pop. */
        return (*env)->PopLocalFrame(env, ret_reg.l);
    }

    const char *sig = vmp_method_sig(method);
    const char *ret_desc = "I";
    if (sig) {
        const char *rp = strchr(sig, ')');
        if (rp && rp[1]) ret_desc = rp + 1;
    }

    if (return_op == VMP_RETURN_WIDE) {
        if (ret_desc[0] == 'D') {
            return (*env)->PopLocalFrame(env, vmp_box_from_reg(env, "D", &ret_reg));
        }
        return (*env)->PopLocalFrame(env, vmp_box_from_reg(env, "J", &ret_reg));
    }

    /* return_op == VMP_RETURN */
    jobject boxed = NULL;
    switch (ret_desc[0]) {
        case 'Z': boxed = vmp_box_from_reg(env, "Z", &ret_reg); break;
        case 'B': boxed = vmp_box_from_reg(env, "B", &ret_reg); break;
        case 'C': boxed = vmp_box_from_reg(env, "C", &ret_reg); break;
        case 'S': boxed = vmp_box_from_reg(env, "S", &ret_reg); break;
        case 'F': boxed = vmp_box_from_reg(env, "F", &ret_reg); break;
        case 'I':
        default:
            boxed = vmp_box_from_reg(env, "I", &ret_reg); break;
    }
    return (*env)->PopLocalFrame(env, boxed);
}

/* --------------------------------------------------------------------- */
/* Jvalue-based arg loading (for JNI stub dispatch)                      */
/* --------------------------------------------------------------------- */

static int vmp_load_jvalue_args(JNIEnv *env, const vmp_method_t *m,
                                 int is_static, jobject thiz,
                                 jvalue *args, int nargs,
                                 vmp_reg_t regs[VMP_MAX_REGS]) {
    vmp_zero_regs(regs, VMP_MAX_REGS);
    const char *sig = vmp_method_sig(m);
    if (!sig) return -1;
    const char *lp = strchr(sig, '(');
    const char *rp = strchr(sig, ')');
    if (!lp || !rp || rp <= lp) return -1;

    int param_start = (int) m->registers_size - (int) m->ins_size;
    if (param_start < 0) param_start = 0;
    int ri = param_start;
    int ai = 0;

    if (!is_static) {
        if (ri < VMP_MAX_REGS) regs[ri].l = thiz;
        ri++;
    }

    const char *p = lp + 1;
    while (p < rp && *p && ai < nargs) {
        if (ri >= VMP_MAX_REGS) break;
        switch (p[0]) {
            case 'Z': VMP_RSET_I(regs[ri], (jint) args[ai].z); break;
            case 'B': VMP_RSET_I(regs[ri], (jint) args[ai].b); break;
            case 'C': VMP_RSET_I(regs[ri], (jint) args[ai].c); break;
            case 'S': VMP_RSET_I(regs[ri], (jint) args[ai].s); break;
            case 'I': VMP_RSET_I(regs[ri], args[ai].i); break;
            case 'J': regs[ri].j = args[ai].j; break;
            case 'F': VMP_RSET_F(regs[ri], args[ai].f); break;
            case 'D': regs[ri].d = args[ai].d; break;
            default:  regs[ri].l = args[ai].l; break;
        }
        int w = (p[0] == 'J' || p[0] == 'D') ? 2 : 1;
        ri += w;
        ai++;
        p = vmp_desc_end(p);
    }
    (void) env;
    return 0;
}

/* --------------------------------------------------------------------- */
/* Public: execute / dispatch                                            */
/* --------------------------------------------------------------------- */

jobject enko_vmp_execute(JNIEnv *env, int method_id, jobject thiz, jobjectArray args) {
    if (!env || !g_vmp.loaded) return NULL;
    if (method_id < 0 || (uint32_t) method_id >= g_vmp.method_count) {
        vmp_throw_runtime(env, "invalid VMP method id");
        return NULL;
    }
    _active_ctx = &g_vmp;
    const vmp_method_t *method = &g_vmp.methods[method_id];
    vmp_reg_t regs[VMP_MAX_REGS];
    vmp_load_entry_args(env, method, thiz, args, regs);
    return vmp_run_interpreter(env, method, regs);
}

__attribute__((visibility("default")))
jobject enko_vmp_dispatch_jvalue(JNIEnv *env, int method_id, int is_static,
                                  jobject thiz, jvalue *args, int nargs) {
    if (!env || !g_vmp.loaded) return NULL;
    if (method_id < 0 || (uint32_t) method_id >= g_vmp.method_count) {
        vmp_throw_runtime(env, "invalid VMP method id");
        return NULL;
    }
    _active_ctx = &g_vmp;
    const vmp_method_t *method = &g_vmp.methods[method_id];
    vmp_reg_t regs[VMP_MAX_REGS];
    if (vmp_load_jvalue_args(env, method, is_static, thiz, args, nargs, regs) != 0) {
        vmp_throw_runtime(env, "VMP dispatch: failed to load jvalue args");
        return NULL;
    }
    return vmp_run_interpreter(env, method, regs);
}

/* --------------------------------------------------------------------- */
/* Public: class-loader binding / native registration hook               */
/* --------------------------------------------------------------------- */

int enko_vmp_register_natives(JNIEnv *env, jobject loader) {
    if (!env) return -1;

    if (g_vmp_loader) {
        (*env)->DeleteGlobalRef(env, g_vmp_loader);
        g_vmp_loader = NULL;
        g_mid_load_class = NULL;
    }

    if (loader) {
        g_vmp_loader = (*env)->NewGlobalRef(env, loader);
        if (!g_vmp_loader) return -1;
        OBFSTR_USE(_cldr, obs_j_classloader, 21);
        jclass clsLoader = (*env)->FindClass(env, _cldr);
        if (!clsLoader) {
            (*env)->DeleteGlobalRef(env, g_vmp_loader);
            g_vmp_loader = NULL;
            return -1;
        }
        g_mid_load_class = (*env)->GetMethodID(env, clsLoader, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
        (*env)->DeleteLocalRef(env, clsLoader);
        if (!g_mid_load_class) {
            (*env)->DeleteGlobalRef(env, g_vmp_loader);
            g_vmp_loader = NULL;
            return -1;
        }
    }

    if (!g_vmp.loaded) return 0;

    /*
     * Try to load VMP stub .so for direct JNI native registration.
     * The stub .so contains per-method JNI functions that call
     * enko_vmp_dispatch_jvalue for efficient typed dispatch.
     */
    int registered = 0;
    OBFSTR_USE(_stub_lib, obs_libstub, 13);
    OBFSTR_USE(_stub_sym, obs_stub_init, 18);
    void *stub_handle = dlopen(_stub_lib, RTLD_NOW);
    if (stub_handle) {
        typedef int (*vmp_stub_init_fn)(JNIEnv *, void *, jobject);
        vmp_stub_init_fn init_fn = (vmp_stub_init_fn) dlsym(stub_handle, _stub_sym);
        if (init_fn) {
            registered = init_fn(env, (void *) enko_vmp_dispatch_jvalue, loader);
            LOGI("VMP stub init: %d method(s) registered", registered);
        } else {
            LOGW("VMP stub .so loaded but enko_vmp_stub_init not found");
        }
        /* Keep handle open — stubs reference function pointers in this lib. */
    } else {
        LOGI("VMP stub .so not found; bridge dispatch fallback: %s", dlerror());
    }

    return registered > 0 ? registered : (int) g_vmp.method_count;
}

/* ===================================================================== */
/* Shell VMP context — separate load/dispatch/register for self-protect  */
/* ===================================================================== */

static void _ctx_free(vmp_context_t *ctx) {
    if (ctx->strings) {
        for (uint32_t i = 0; i < ctx->string_count; ++i) {
            free(ctx->strings[i]);
        }
        free(ctx->strings);
    }
    free(ctx->methods);
    free(ctx->bytecode);
    if (ctx->method_tries) {
        for (uint32_t i = 0; i < ctx->method_count; ++i) {
            vmp_method_tries_t *mt = &ctx->method_tries[i];
            if (mt->tries) {
                for (uint16_t t = 0; t < mt->try_count; ++t) {
                    free(mt->tries[t].handlers);
                }
                free(mt->tries);
            }
        }
        free(ctx->method_tries);
    }
    memset(ctx, 0, sizeof(*ctx));
}

static int _ctx_load(vmp_context_t *ctx, const uint8_t *blob, size_t blob_len) {
    if (!blob || blob_len < 12 + 4 + 256 + 4 + 4) return -1;

    _ctx_free(ctx);

    /* Decrypt VMP magic on first call. */
    if (kVmpMagic[0] == 0) {
        obs_vmp_magic_dec((char *)kVmpMagic, 11);
        kVmpMagic[11] = '\0';
    }

    blob_reader_t r;
    r.buf = blob;
    r.len = blob_len;
    r.off = 0;

    uint8_t magic[12];
    if (rd_bytes(&r, magic, sizeof(magic)) != 0) goto fail;
    if (memcmp(magic, kVmpMagic, sizeof(kVmpMagic)) != 0) {
        LOGE("shell VMP blob magic mismatch");
        goto fail;
    }

    uint32_t version = 0;
    if (rd_u32(&r, &version) != 0) goto fail;
    if (version != kVmpVersion) {
        LOGE("shell VMP blob version mismatch: got=%u expected=%u", version, kVmpVersion);
        goto fail;
    }

    if (rd_bytes(&r, ctx->opcode_table, 256) != 0) goto fail;

    uint32_t string_salt = 0;
    if (rd_u32(&r, &string_salt) != 0) goto fail;
    if (rd_u32(&r, &ctx->string_count) != 0) goto fail;
    if (ctx->string_count > 1000000U) goto fail;
    if (ctx->string_count > 0) {
        ctx->strings = (char **) calloc(ctx->string_count, sizeof(char *));
        if (!ctx->strings) goto fail;
    }
    for (uint32_t i = 0; i < ctx->string_count; ++i) {
        uint16_t n = 0;
        if (rd_u16(&r, &n) != 0) goto fail;
        if (r.off + n > r.len) goto fail;
        ctx->strings[i] = (char *) malloc((size_t) n + 1);
        if (!ctx->strings[i]) goto fail;
        memcpy(ctx->strings[i], r.buf + r.off, n);
        vmp_crypt_string((uint8_t *)ctx->strings[i], n, string_salt, i);
        ctx->strings[i][n] = '\0';
        r.off += n;
    }

    if (rd_u32(&r, &ctx->method_count) != 0) goto fail;
    if (ctx->method_count > 100000U) goto fail;
    if (ctx->method_count > 0) {
        ctx->methods = (vmp_method_t *) calloc(ctx->method_count, sizeof(vmp_method_t));
        if (!ctx->methods) goto fail;
    }
    for (uint32_t i = 0; i < ctx->method_count; ++i) {
        vmp_method_t *m = &ctx->methods[i];
        if (rd_u32(&r, &m->method_id) != 0) goto fail;
        if (rd_u32(&r, &m->class_name_idx) != 0) goto fail;
        if (rd_u32(&r, &m->method_name_idx) != 0) goto fail;
        if (rd_u32(&r, &m->method_sig_idx) != 0) goto fail;
        if (rd_u16(&r, &m->registers_size) != 0) goto fail;
        if (rd_u16(&r, &m->ins_size) != 0) goto fail;
        if (rd_u16(&r, &m->outs_size) != 0) goto fail;
        if (rd_u16(&r, &m->tries_count) != 0) goto fail;
        if (rd_i32(&r, &m->op_obfs_seed) != 0) goto fail;
        if (rd_i32(&r, &m->bytecode_off) != 0) goto fail;
        if (rd_i32(&r, &m->bytecode_size) != 0) goto fail;
    }

    if (rd_u32(&r, &ctx->bytecode_size) != 0) goto fail;
    if (ctx->bytecode_size > 0) {
        if (r.off + ctx->bytecode_size > r.len) goto fail;
        ctx->bytecode = (uint8_t *) malloc(ctx->bytecode_size);
        if (!ctx->bytecode) goto fail;
        memcpy(ctx->bytecode, r.buf + r.off, ctx->bytecode_size);
        r.off += ctx->bytecode_size;
    }

    /* Parse try-catch section */
    if (ctx->method_count > 0) {
        ctx->method_tries = (vmp_method_tries_t *) calloc(ctx->method_count, sizeof(vmp_method_tries_t));
        if (!ctx->method_tries) goto fail;
    }
    for (uint32_t i = 0; i < ctx->method_count; ++i) {
        vmp_method_tries_t *mt = &ctx->method_tries[i];
        if (rd_u16(&r, &mt->try_count) != 0) goto fail;
        if (mt->try_count > 0) {
            mt->tries = (vmp_try_block_t *) calloc(mt->try_count, sizeof(vmp_try_block_t));
            if (!mt->tries) goto fail;
        }
        for (uint16_t t = 0; t < mt->try_count; ++t) {
            vmp_try_block_t *tb = &mt->tries[t];
            if (rd_u16(&r, &tb->start_pc) != 0) goto fail;
            if (rd_u16(&r, &tb->end_pc) != 0) goto fail;
            if (rd_u16(&r, &tb->handler_count) != 0) goto fail;
            if (tb->handler_count > 0) {
                tb->handlers = (vmp_catch_handler_t *) calloc(tb->handler_count, sizeof(vmp_catch_handler_t));
                if (!tb->handlers) goto fail;
            }
            for (uint16_t h = 0; h < tb->handler_count; ++h) {
                if (rd_i32(&r, &tb->handlers[h].type_str_idx) != 0) goto fail;
                if (rd_i32(&r, &tb->handlers[h].handler_pc) != 0) goto fail;
            }
            if (rd_i32(&r, &tb->catch_all_pc) != 0) goto fail;
        }
    }

    ctx->loaded = 1;
    ctx->core_tier = VMP_TIER_LIGHT;
    return 0;

fail:
    LOGE("VMP blob parse failed at offset=%zu", r.off);
    _ctx_free(ctx);
    return -1;
}

int enko_vmp_shell_load(const uint8_t *blob, size_t blob_len) {
    int rc = _ctx_load(&g_vmp_shell, blob, blob_len);
    if (rc == 0) {
        LOGI("shell VMP blob loaded: strings=%u methods=%u bytecode=%u tier=%s",
             g_vmp_shell.string_count, g_vmp_shell.method_count,
             g_vmp_shell.bytecode_size, vmp_tier_name(g_vmp_shell.core_tier));
    }
    return rc;
}

int enko_vmp_shell_set_tier(int tier) {
    g_vmp_shell.core_tier = vmp_clamp_tier(tier);
    LOGI("shell VMP core tier selected: %s", vmp_tier_name(g_vmp_shell.core_tier));
    return 0;
}

__attribute__((visibility("default")))
jobject enko_vmp_shell_dispatch_jvalue(JNIEnv *env, int method_id, int is_static,
                                        jobject thiz, jvalue *args, int nargs) {
    if (!env || !g_vmp_shell.loaded) return NULL;
    if (method_id < 0 || (uint32_t) method_id >= g_vmp_shell.method_count) {
        vmp_throw_runtime(env, "invalid shell VMP method id");
        return NULL;
    }
    _active_ctx = &g_vmp_shell;
    const vmp_method_t *method = &g_vmp_shell.methods[method_id];
    vmp_reg_t regs[VMP_MAX_REGS];
    if (vmp_load_jvalue_args(env, method, is_static, thiz, args, nargs, regs) != 0) {
        vmp_throw_runtime(env, "shell VMP dispatch: failed to load jvalue args");
        return NULL;
    }
    return vmp_run_interpreter(env, method, regs);
}

int enko_vmp_shell_register_natives(JNIEnv *env, jobject loader) {
    if (!env) return -1;

    if (g_vmp_shell_loader) {
        (*env)->DeleteGlobalRef(env, g_vmp_shell_loader);
        g_vmp_shell_loader = NULL;
        g_mid_shell_load_class = NULL;
    }

    if (loader) {
        g_vmp_shell_loader = (*env)->NewGlobalRef(env, loader);
        if (!g_vmp_shell_loader) return -1;
        jclass clsLoader = (*env)->FindClass(env, "java/lang/ClassLoader");
        if (!clsLoader) {
            (*env)->DeleteGlobalRef(env, g_vmp_shell_loader);
            g_vmp_shell_loader = NULL;
            return -1;
        }
        g_mid_shell_load_class = (*env)->GetMethodID(env, clsLoader, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
        (*env)->DeleteLocalRef(env, clsLoader);
        if (!g_mid_shell_load_class) {
            (*env)->DeleteGlobalRef(env, g_vmp_shell_loader);
            g_vmp_shell_loader = NULL;
            return -1;
        }
    }

    if (!g_vmp_shell.loaded) return 0;

    int registered = 0;
    void *stub_handle = dlopen("libagpshvmp.so", RTLD_NOW);
    if (stub_handle) {
        typedef int (*vmp_stub_init_fn)(JNIEnv *, void *, jobject);
        vmp_stub_init_fn init_fn = (vmp_stub_init_fn) dlsym(stub_handle, "enko_vmp_stub_init");
        if (init_fn) {
            registered = init_fn(env, (void *) enko_vmp_shell_dispatch_jvalue, loader);
            LOGI("shell VMP stub init: %d method(s) registered", registered);
        } else {
            LOGW("shell VMP stub .so loaded but init symbol not found");
        }
    } else {
        LOGI("shell VMP stub .so not found: %s", dlerror());
    }

    return registered > 0 ? registered : (int) g_vmp_shell.method_count;
}

void enko_vmp_shell_free(void) {
    _ctx_free(&g_vmp_shell);
}
