#ifndef ENKO_VMP_H
#define ENKO_VMP_H

#include <jni.h>
#include <stdint.h>
#include <stddef.h>

/* ── VMP operation IDs (must match Python VmpOp enum) ────────────────── */

enum {
    VMP_NOP = 0,
    VMP_MOVE, VMP_MOVE_WIDE, VMP_MOVE_OBJECT,
    VMP_MOVE_RESULT, VMP_MOVE_RESULT_WIDE, VMP_MOVE_RESULT_OBJECT,
    VMP_MOVE_EXCEPTION,
    VMP_RETURN_VOID, VMP_RETURN, VMP_RETURN_WIDE, VMP_RETURN_OBJECT,
    VMP_CONST, VMP_CONST_WIDE, VMP_CONST_STRING, VMP_CONST_CLASS,
    VMP_MONITOR_ENTER, VMP_MONITOR_EXIT,
    VMP_CHECK_CAST, VMP_INSTANCE_OF,
    VMP_NEW_INSTANCE, VMP_NEW_ARRAY, VMP_ARRAY_LENGTH,
    VMP_THROW, VMP_GOTO,
    VMP_IF_EQ, VMP_IF_NE, VMP_IF_LT, VMP_IF_GE, VMP_IF_GT, VMP_IF_LE,
    VMP_IF_EQZ, VMP_IF_NEZ, VMP_IF_LTZ, VMP_IF_GEZ, VMP_IF_GTZ, VMP_IF_LEZ,
    VMP_AGET, VMP_AGET_WIDE, VMP_AGET_OBJECT,
    VMP_AGET_BOOLEAN, VMP_AGET_BYTE, VMP_AGET_CHAR, VMP_AGET_SHORT,
    VMP_APUT, VMP_APUT_WIDE, VMP_APUT_OBJECT,
    VMP_APUT_BOOLEAN, VMP_APUT_BYTE, VMP_APUT_CHAR, VMP_APUT_SHORT,
    VMP_IGET, VMP_IGET_WIDE, VMP_IGET_OBJECT,
    VMP_IGET_BOOLEAN, VMP_IGET_BYTE, VMP_IGET_CHAR, VMP_IGET_SHORT,
    VMP_IPUT, VMP_IPUT_WIDE, VMP_IPUT_OBJECT,
    VMP_IPUT_BOOLEAN, VMP_IPUT_BYTE, VMP_IPUT_CHAR, VMP_IPUT_SHORT,
    VMP_SGET, VMP_SGET_WIDE, VMP_SGET_OBJECT,
    VMP_SGET_BOOLEAN, VMP_SGET_BYTE, VMP_SGET_CHAR, VMP_SGET_SHORT,
    VMP_SPUT, VMP_SPUT_WIDE, VMP_SPUT_OBJECT,
    VMP_SPUT_BOOLEAN, VMP_SPUT_BYTE, VMP_SPUT_CHAR, VMP_SPUT_SHORT,
    VMP_INVOKE_VIRTUAL, VMP_INVOKE_SUPER, VMP_INVOKE_DIRECT,
    VMP_INVOKE_STATIC, VMP_INVOKE_INTERFACE,
    VMP_NEG_INT, VMP_NOT_INT, VMP_NEG_LONG, VMP_NOT_LONG,
    VMP_NEG_FLOAT, VMP_NEG_DOUBLE,
    VMP_INT_TO_LONG, VMP_INT_TO_FLOAT, VMP_INT_TO_DOUBLE,
    VMP_LONG_TO_INT, VMP_LONG_TO_FLOAT, VMP_LONG_TO_DOUBLE,
    VMP_FLOAT_TO_INT, VMP_FLOAT_TO_LONG, VMP_FLOAT_TO_DOUBLE,
    VMP_DOUBLE_TO_INT, VMP_DOUBLE_TO_LONG, VMP_DOUBLE_TO_FLOAT,
    VMP_INT_TO_BYTE, VMP_INT_TO_CHAR, VMP_INT_TO_SHORT,
    VMP_ADD_INT, VMP_SUB_INT, VMP_MUL_INT, VMP_DIV_INT, VMP_REM_INT,
    VMP_AND_INT, VMP_OR_INT, VMP_XOR_INT,
    VMP_SHL_INT, VMP_SHR_INT, VMP_USHR_INT,
    VMP_ADD_LONG, VMP_SUB_LONG, VMP_MUL_LONG, VMP_DIV_LONG, VMP_REM_LONG,
    VMP_AND_LONG, VMP_OR_LONG, VMP_XOR_LONG,
    VMP_SHL_LONG, VMP_SHR_LONG, VMP_USHR_LONG,
    VMP_ADD_FLOAT, VMP_SUB_FLOAT, VMP_MUL_FLOAT, VMP_DIV_FLOAT, VMP_REM_FLOAT,
    VMP_ADD_DOUBLE, VMP_SUB_DOUBLE, VMP_MUL_DOUBLE, VMP_DIV_DOUBLE, VMP_REM_DOUBLE,
    VMP_CMP_LONG, VMP_CMPG_FLOAT, VMP_CMPL_FLOAT,
    VMP_CMPG_DOUBLE, VMP_CMPL_DOUBLE,
    VMP_PACKED_SWITCH, VMP_SPARSE_SWITCH,
    VMP_FILL_ARRAY_DATA, VMP_FILLED_NEW_ARRAY,
    VMP_INVOKE_ARGS,
    VMP_CONST_WIDE_HI32,
    VMP_INVOKE_CUSTOM,
    VMP_INVOKE_POLYMORPHIC,

    /* Alias opcodes (150-199) — per-build random assignment.
     * Interpreter maps them back to canonical handlers. */
    VMP_BINOP_ALIAS1, VMP_BINOP_ALIAS2, VMP_BINOP_ALIAS3, VMP_BINOP_ALIAS4,
    VMP_BINOP_ALIAS5, VMP_BINOP_ALIAS6, VMP_BINOP_ALIAS7, VMP_BINOP_ALIAS8,
    VMP_BINOP_ALIAS9, VMP_BINOP_ALIAS10,
    VMP_UNOP_ALIAS1, VMP_UNOP_ALIAS2, VMP_UNOP_ALIAS3, VMP_UNOP_ALIAS4,
    VMP_UNOP_ALIAS5,
    VMP_BINOP_LIT_ALIAS1, VMP_BINOP_LIT_ALIAS2, VMP_BINOP_LIT_ALIAS3,
    VMP_BINOP_LIT_ALIAS4, VMP_BINOP_LIT_ALIAS5, VMP_BINOP_LIT_ALIAS6,
    VMP_BINOP_LIT_ALIAS7, VMP_BINOP_LIT_ALIAS8,
    VMP_IF_ALIAS1, VMP_IF_ALIAS2, VMP_IF_ALIAS3, VMP_IF_ALIAS4,
    VMP_IF_ALIAS5, VMP_IF_ALIAS6,
    VMP_IFZ_ALIAS1, VMP_IFZ_ALIAS2, VMP_IFZ_ALIAS3, VMP_IFZ_ALIAS4,
    VMP_IFZ_ALIAS5, VMP_IFZ_ALIAS6,
    VMP_AGET_ALIAS1, VMP_AGET_ALIAS2, VMP_AGET_ALIAS3, VMP_AGET_ALIAS4,
    VMP_APUT_ALIAS1, VMP_APUT_ALIAS2, VMP_APUT_ALIAS3, VMP_APUT_ALIAS4,
    VMP_IGET_ALIAS1, VMP_IGET_ALIAS2, VMP_IGET_ALIAS3,
    VMP_IPUT_ALIAS1, VMP_IPUT_ALIAS2, VMP_IPUT_ALIAS3,
    VMP_SGET_SPUT_ALIAS1,

    VMP_OP_COUNT
};

#define VMP_OP_COUNT_VALUE 200

enum {
    VMP_TIER_COMPAT = 0,
    VMP_TIER_LIGHT = 1,
    VMP_TIER_STRONG = 2
};

/* ── VMP instruction (8 bytes, fixed width) ─────────────────────────── */

typedef struct {
    uint8_t  opcode;   /* shuffled opcode */
    uint8_t  dst;
    uint8_t  src1;
    uint8_t  src2;
    int32_t  imm;
} __attribute__((packed)) vmp_insn_t;

/* ── VMP method descriptor (from blob) ──────────────────────────────── */

typedef struct {
    uint32_t method_id;
    uint32_t class_name_idx;
    uint32_t method_name_idx;
    uint32_t method_sig_idx;
    uint16_t registers_size;
    uint16_t ins_size;
    uint16_t outs_size;
    uint16_t tries_count;
    int32_t  op_obfs_seed;   /* LFSR seed for operand de-scrambling (0=none) */
    int32_t  bytecode_off;
    int32_t  bytecode_size;
} __attribute__((packed)) vmp_method_t;

/* ── VMP try-catch structures ───────────────────────────────────────── */

typedef struct {
    int32_t type_str_idx;   /* string pool index of exception type, -1 = untyped */
    int32_t handler_pc;     /* VMP insn index to jump to */
} vmp_catch_handler_t;

typedef struct {
    uint16_t start_pc;      /* VMP insn index (inclusive) */
    uint16_t end_pc;        /* VMP insn index (exclusive) */
    uint16_t handler_count;
    vmp_catch_handler_t *handlers;
    int32_t catch_all_pc;   /* VMP insn index, -1 if no catch-all */
} vmp_try_block_t;

typedef struct {
    uint16_t try_count;
    vmp_try_block_t *tries;
} vmp_method_tries_t;

/* ── VMP runtime context ────────────────────────────────────────────── */

#define VMP_MAX_REGS 256

typedef union {
    int32_t  i;
    int64_t  j;
    float    f;
    double   d;
    jobject  l;
} vmp_reg_t;

typedef struct {
    /* Parsed from blob */
    uint8_t       opcode_table[256]; /* shuffled → real_op */
    uint32_t      string_count;
    char        **strings;           /* string pool (UTF-8) */
    uint32_t      method_count;
    vmp_method_t *methods;
    uint8_t      *bytecode;          /* all methods' bytecodes */
    uint32_t      bytecode_size;
    vmp_method_tries_t *method_tries; /* per-method try-catch tables */
    int           core_tier;          /* VMP_TIER_* runtime core profile */
    /* Loaded flag */
    int           loaded;
} vmp_context_t;

/* ── Public API ──────────────────────────────────────────────────────── */

/**
 * Parse VMP blob into the global context.
 * Returns 0 on success, -1 on error.
 */
int enko_vmp_load(const uint8_t *blob, size_t blob_len);

/** Select payload VMP interpreter core tier (VMP_TIER_*). */
int enko_vmp_set_tier(int tier);

/**
 * Execute a VMP-protected method.
 *
 * @param env       JNI environment
 * @param method_id VMP method index
 * @param thiz      `this` object (NULL for static methods)
 * @param args      argument array (jobjectArray)
 * @return          boxed return value (jobject) or NULL for void
 */
jobject enko_vmp_execute(JNIEnv *env, int method_id, jobject thiz, jobjectArray args);

/**
 * Efficient jvalue-based VMP dispatch (used by JNI stubs).
 *
 * @param env       JNI environment
 * @param method_id VMP method index
 * @param is_static 1 if method is static, 0 otherwise
 * @param thiz      `this` object (NULL for static methods)
 * @param args      typed jvalue argument array (excludes receiver)
 * @param nargs     number of elements in @p args
 * @return          boxed return value (jobject) or NULL for void
 */
jobject enko_vmp_dispatch_jvalue(JNIEnv *env, int method_id, int is_static,
                                  jobject thiz, jvalue *args, int nargs);

/**
 * Register JNI native methods for all VMP-protected methods.
 * Must be called after the payload ClassLoader is established.
 *
 * @param env    JNI environment
 * @param loader ClassLoader that loaded the payload DEX
 * @return       number of methods registered, or -1 on error
 */
int enko_vmp_register_natives(JNIEnv *env, jobject loader);

/** Free VMP context resources. */
void enko_vmp_free(void);

/* ── Shell VMP (second context for self-protection) ─────────────────── */

/** Load shell VMP blob into the separate shell context. */
int enko_vmp_shell_load(const uint8_t *blob, size_t blob_len);

/** Select shell VMP interpreter core tier (VMP_TIER_*). */
int enko_vmp_shell_set_tier(int tier);

/** Dispatch for shell VMP (uses g_vmp_shell context). */
jobject enko_vmp_shell_dispatch_jvalue(JNIEnv *env, int method_id, int is_static,
                                        jobject thiz, jvalue *args, int nargs);

/** Register shell VMP JNI stubs (dlopen's libagpshvmp.so). */
int enko_vmp_shell_register_natives(JNIEnv *env, jobject loader);

/** Free shell VMP context resources. */
void enko_vmp_shell_free(void);

#endif /* ENKO_VMP_H */
