#include <jni.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <ctype.h>
#include <limits.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>

#include <android/log.h>

#include "enko_gcm.h"
#include "enko_key.h"
#include "enko_anti_debug.h"
#include "enko_anti_dump.h"
#include "enko_integrity.h"
#include "enko_vmp.h"
#include "enko_extract.h"
#include "enko_obfstr.h"

#include <dlfcn.h>  /* dlopen, dlsym for DEX2C */

/* "EnkoNative" (len=10) — obfuscated TAG */
OBFSTR_DECL(obs_jni_tag, 0x82,0xA9,0xAC,0xA8,0x89,0xA6,0xB3,0xAE,0xB1,0xA2);
static char g_jni_tag[11];
static void ensure_jni_tag(void) {
    if (g_jni_tag[0] == '\0') obs_jni_tag_dec(g_jni_tag, 10);
}
#define LOGI(...) do { ensure_jni_tag(); __android_log_print(ANDROID_LOG_INFO,  g_jni_tag, __VA_ARGS__); } while(0)
#define LOGW(...) do { ensure_jni_tag(); __android_log_print(ANDROID_LOG_WARN,  g_jni_tag, __VA_ARGS__); } while(0)
#define LOGE(...) do { ensure_jni_tag(); __android_log_print(ANDROID_LOG_ERROR, g_jni_tag, __VA_ARGS__); } while(0)

/* Native identity gate:
 * 0 = not verified (or failed)
 * 1 = verified in nativeDecryptConfig
 */
static volatile int g_runtime_identity_verified = 0;
static volatile int g_shell_dex_verified = 0;
static volatile int g_native_libs_verified = 0;
static volatile int g_libapp_verified = 0;
static volatile int g_libflutter_verified = 0;
static volatile int g_rollback_guard_verified = 0;
static volatile int g_startup_risk_verified = 0;

typedef struct runtime_cfg_expect_t {
    char expected_pkg[256];
    char expected_sign_sha256[65];
    char shell_dex_sha256[65];
    char native_libs_sha256[65];
    char libapp_sha256[65];
    char libflutter_sha256[65];
    char build_id[65];
    long long build_epoch_sec;
    long long build_version_code;
    char risk_policy[16];
    char risk_profile[16];
    int detect_root;
    int detect_emulator;
    int block_proxy_vpn;
    int require_shell_dex;
    int require_native_libs;
    int require_libapp;
    int require_libflutter;
} runtime_cfg_expect_t;

static runtime_cfg_expect_t g_cfg_expect;

static void reset_runtime_gates(void) {
    memset(&g_cfg_expect, 0, sizeof(g_cfg_expect));
    g_runtime_identity_verified = 0;
    g_shell_dex_verified = 0;
    g_native_libs_verified = 0;
    g_libapp_verified = 0;
    g_libflutter_verified = 0;
    g_rollback_guard_verified = 0;
    g_startup_risk_verified = 0;
}

static int b64_char_value(char c) {
    if (c >= 'A' && c <= 'Z') return (int)(c - 'A');
    if (c >= 'a' && c <= 'z') return (int)(c - 'a') + 26;
    if (c >= '0' && c <= '9') return (int)(c - '0') + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int b64_decode(
        const char *in, size_t in_len,
        uint8_t *out, size_t out_cap,
        size_t *out_len) {
    if (!in || !out || !out_len) return -1;
    size_t i = 0;
    size_t o = 0;
    while (i < in_len) {
        int vals[4];
        int got = 0;
        while (got < 4) {
            if (i >= in_len) {
                return -1;
            }
            unsigned char c = (unsigned char)in[i++];
            if (isspace(c)) {
                continue;
            }
            if (c == '=') {
                vals[got++] = -2;
                continue;
            }
            int v = b64_char_value((char)c);
            if (v < 0) {
                return -1;
            }
            vals[got++] = v;
        }
        if (vals[0] < 0 || vals[1] < 0) return -1;
        if (o + 1 > out_cap) return -1;
        out[o++] = (uint8_t)((vals[0] << 2) | (vals[1] >> 4));
        if (vals[2] == -2) {
            if (vals[3] != -2) return -1;
            break;
        }
        if (vals[2] < 0) return -1;
        if (o + 1 > out_cap) return -1;
        out[o++] = (uint8_t)(((vals[1] & 0x0F) << 4) | (vals[2] >> 2));
        if (vals[3] == -2) {
            break;
        }
        if (vals[3] < 0) return -1;
        if (o + 1 > out_cap) return -1;
        out[o++] = (uint8_t)(((vals[2] & 0x03) << 6) | vals[3]);
    }
    *out_len = o;
    return 0;
}

static void trim_ascii_inplace(char *s) {
    if (!s) return;
    size_t len = strlen(s);
    size_t start = 0;
    while (start < len && isspace((unsigned char)s[start])) {
        start++;
    }
    size_t end = len;
    while (end > start && isspace((unsigned char)s[end - 1])) {
        end--;
    }
    if (start > 0 && end > start) {
        memmove(s, s + start, end - start);
    }
    s[end - start] = '\0';
}

static int normalize_sha256_hex_inplace(char *s) {
    if (!s) return -1;
    size_t r = 0;
    size_t w = 0;
    while (s[r] != '\0') {
        unsigned char c = (unsigned char)s[r++];
        if (c == ':' || c == '-' || isspace(c)) {
            continue;
        }
        if (!isxdigit(c)) {
            return -1;
        }
        if (w >= 64) {
            return -1;
        }
        s[w++] = (char)toupper(c);
    }
    if (w != 64) {
        return -1;
    }
    s[w] = '\0';
    return 0;
}

static void lowercase_ascii_inplace(char *s) {
    if (!s) return;
    for (size_t i = 0; s[i] != '\0'; i++) {
        s[i] = (char)tolower((unsigned char)s[i]);
    }
}

static int parse_bool_01(const char *s, int *out) {
    if (!s || !out) return -1;
    if (strcmp(s, "1") == 0 || strcasecmp(s, "true") == 0) {
        *out = 1;
        return 0;
    }
    if (strcmp(s, "0") == 0 || strcasecmp(s, "false") == 0) {
        *out = 0;
        return 0;
    }
    return -1;
}

static int parse_nonneg_int64(const char *s, long long *out) {
    if (!s || !out) return -1;
    char *end = NULL;
    long long v = strtoll(s, &end, 10);
    if (end == s || *end != '\0' || v < 0) {
        return -1;
    }
    *out = v;
    return 0;
}

static int cfg_get_decoded_value(
        const uint8_t *cfg, size_t cfg_len,
        const char *key,
        char *out, size_t out_cap) {
    if (!cfg || !key || !out || out_cap < 2) {
        return -1;
    }
    const size_t key_len = strlen(key);
    size_t i = 0;
    while (i < cfg_len) {
        size_t line_start = i;
        while (i < cfg_len && cfg[i] != '\n' && cfg[i] != '\r') {
            i++;
        }
        size_t line_end = i;
        while (i < cfg_len && (cfg[i] == '\n' || cfg[i] == '\r')) {
            i++;
        }
        if (line_end <= line_start) {
            continue;
        }
        size_t eq = (size_t)-1;
        for (size_t p = line_start; p < line_end; p++) {
            if (cfg[p] == '=') {
                eq = p;
                break;
            }
        }
        if (eq == (size_t)-1 || eq == line_start) {
            continue;
        }
        size_t klen = eq - line_start;
        if (klen != key_len || memcmp(cfg + line_start, key, key_len) != 0) {
            continue;
        }
        const char *b64 = (const char *)(cfg + eq + 1);
        size_t b64_len = line_end - (eq + 1);
        while (b64_len > 0 && isspace((unsigned char)b64[0])) {
            b64++;
            b64_len--;
        }
        while (b64_len > 0 && isspace((unsigned char)b64[b64_len - 1])) {
            b64_len--;
        }
        size_t decoded_len = 0;
        if (b64_decode(
                b64,
                b64_len,
                (uint8_t *)out,
                out_cap - 1,
                &decoded_len) != 0) {
            return -1;
        }
        out[decoded_len] = '\0';
        trim_ascii_inplace(out);
        return 0;
    }
    return -1;
}

static int load_runtime_expect_from_cfg(const uint8_t *cfg, size_t cfg_len) {
    char tmp[256];
    memset(&g_cfg_expect, 0, sizeof(g_cfg_expect));

    if (cfg_get_decoded_value(
            cfg,
            cfg_len,
            "expectedPackageName",
            g_cfg_expect.expected_pkg,
            sizeof(g_cfg_expect.expected_pkg)) != 0) {
        return -1;
    }
    if (g_cfg_expect.expected_pkg[0] == '\0') {
        return -1;
    }
    if (cfg_get_decoded_value(
            cfg,
            cfg_len,
            "expectedSignSha256",
            g_cfg_expect.expected_sign_sha256,
            sizeof(g_cfg_expect.expected_sign_sha256)) != 0) {
        return -1;
    }
    if (normalize_sha256_hex_inplace(g_cfg_expect.expected_sign_sha256) != 0) {
        return -1;
    }

    if (cfg_get_decoded_value(
            cfg,
            cfg_len,
            "shellDexSha256",
            tmp,
            sizeof(tmp)) == 0 &&
            tmp[0] != '\0') {
        if (normalize_sha256_hex_inplace(tmp) != 0) {
            return -1;
        }
        memcpy(g_cfg_expect.shell_dex_sha256, tmp, sizeof(g_cfg_expect.shell_dex_sha256));
        g_cfg_expect.require_shell_dex = 1;
    }

    memset(tmp, 0, sizeof(tmp));
    if (cfg_get_decoded_value(
            cfg,
            cfg_len,
            "nativeLibsSha256",
            tmp,
            sizeof(tmp)) == 0 &&
            tmp[0] != '\0') {
        if (normalize_sha256_hex_inplace(tmp) != 0) {
            return -1;
        }
        memcpy(g_cfg_expect.native_libs_sha256, tmp, sizeof(g_cfg_expect.native_libs_sha256));
        g_cfg_expect.require_native_libs = 1;
    }

    memset(tmp, 0, sizeof(tmp));
    if (cfg_get_decoded_value(
            cfg,
            cfg_len,
            "libAppSha256",
            tmp,
            sizeof(tmp)) == 0 &&
            tmp[0] != '\0') {
        if (normalize_sha256_hex_inplace(tmp) != 0) {
            return -1;
        }
        memcpy(g_cfg_expect.libapp_sha256, tmp, sizeof(g_cfg_expect.libapp_sha256));
        g_cfg_expect.require_libapp = 1;
    }

    memset(tmp, 0, sizeof(tmp));
    if (cfg_get_decoded_value(
            cfg,
            cfg_len,
            "libFlutterSha256",
            tmp,
            sizeof(tmp)) == 0 &&
            tmp[0] != '\0') {
        if (normalize_sha256_hex_inplace(tmp) != 0) {
            return -1;
        }
        memcpy(g_cfg_expect.libflutter_sha256, tmp, sizeof(g_cfg_expect.libflutter_sha256));
        g_cfg_expect.require_libflutter = 1;
    }

    memset(tmp, 0, sizeof(tmp));
    if (cfg_get_decoded_value(cfg, cfg_len, "buildId", tmp, sizeof(tmp)) == 0 && tmp[0] != '\0') {
        size_t n = strlen(tmp);
        if (n >= sizeof(g_cfg_expect.build_id)) {
            n = sizeof(g_cfg_expect.build_id) - 1;
        }
        memcpy(g_cfg_expect.build_id, tmp, n);
        g_cfg_expect.build_id[n] = '\0';
        for (size_t i = 0; g_cfg_expect.build_id[i] != '\0'; i++) {
            unsigned char c = (unsigned char)g_cfg_expect.build_id[i];
            if (!isxdigit(c)) {
                return -1;
            }
            g_cfg_expect.build_id[i] = (char)toupper(c);
        }
    }

    memset(tmp, 0, sizeof(tmp));
    if (cfg_get_decoded_value(cfg, cfg_len, "buildEpochSec", tmp, sizeof(tmp)) == 0 && tmp[0] != '\0') {
        if (parse_nonneg_int64(tmp, &g_cfg_expect.build_epoch_sec) != 0) {
            return -1;
        }
    }

    memset(tmp, 0, sizeof(tmp));
    if (cfg_get_decoded_value(cfg, cfg_len, "buildVersionCode", tmp, sizeof(tmp)) == 0 && tmp[0] != '\0') {
        if (parse_nonneg_int64(tmp, &g_cfg_expect.build_version_code) != 0) {
            return -1;
        }
    }

    memset(tmp, 0, sizeof(tmp));
    if (cfg_get_decoded_value(cfg, cfg_len, "riskPolicy", tmp, sizeof(tmp)) == 0 && tmp[0] != '\0') {
        lowercase_ascii_inplace(tmp);
        if (strcmp(tmp, "block") != 0 && strcmp(tmp, "degrade") != 0 &&
            strcmp(tmp, "warn") != 0 && strcmp(tmp, "log") != 0 &&
            strcmp(tmp, "off") != 0) {
            return -1;
        }
        strncpy(g_cfg_expect.risk_policy, tmp, sizeof(g_cfg_expect.risk_policy) - 1);
        g_cfg_expect.risk_policy[sizeof(g_cfg_expect.risk_policy) - 1] = '\0';
    } else {
        strncpy(g_cfg_expect.risk_policy, "block", sizeof(g_cfg_expect.risk_policy) - 1);
        g_cfg_expect.risk_policy[sizeof(g_cfg_expect.risk_policy) - 1] = '\0';
    }

    memset(tmp, 0, sizeof(tmp));
    if (cfg_get_decoded_value(cfg, cfg_len, "riskProfile", tmp, sizeof(tmp)) == 0 && tmp[0] != '\0') {
        lowercase_ascii_inplace(tmp);
        if (strcmp(tmp, "strict") != 0 && strcmp(tmp, "balanced") != 0 && strcmp(tmp, "compat") != 0) {
            return -1;
        }
        strncpy(g_cfg_expect.risk_profile, tmp, sizeof(g_cfg_expect.risk_profile) - 1);
        g_cfg_expect.risk_profile[sizeof(g_cfg_expect.risk_profile) - 1] = '\0';
    } else {
        strncpy(g_cfg_expect.risk_profile, "balanced", sizeof(g_cfg_expect.risk_profile) - 1);
        g_cfg_expect.risk_profile[sizeof(g_cfg_expect.risk_profile) - 1] = '\0';
    }

    memset(tmp, 0, sizeof(tmp));
    if (cfg_get_decoded_value(cfg, cfg_len, "detectRoot", tmp, sizeof(tmp)) == 0 && tmp[0] != '\0') {
        if (parse_bool_01(tmp, &g_cfg_expect.detect_root) != 0) {
            return -1;
        }
    } else {
        g_cfg_expect.detect_root = 1;
    }

    memset(tmp, 0, sizeof(tmp));
    if (cfg_get_decoded_value(cfg, cfg_len, "detectEmulator", tmp, sizeof(tmp)) == 0 && tmp[0] != '\0') {
        if (parse_bool_01(tmp, &g_cfg_expect.detect_emulator) != 0) {
            return -1;
        }
    } else {
        g_cfg_expect.detect_emulator = 1;
    }

    memset(tmp, 0, sizeof(tmp));
    if (cfg_get_decoded_value(cfg, cfg_len, "blockProxyVpn", tmp, sizeof(tmp)) == 0 && tmp[0] != '\0') {
        if (parse_bool_01(tmp, &g_cfg_expect.block_proxy_vpn) != 0) {
            return -1;
        }
    } else {
        g_cfg_expect.block_proxy_vpn = 1;
    }
    return 0;
}

static jobject get_current_application(JNIEnv *env) {
    jobject app = NULL;
    jclass at_cls = (*env)->FindClass(env, "android/app/ActivityThread");
    if (!at_cls) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        return NULL;
    }
    jmethodID mid_current_application = (*env)->GetStaticMethodID(
            env,
            at_cls,
            "currentApplication",
            "()Landroid/app/Application;");
    if (!mid_current_application) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, at_cls);
        return NULL;
    }
    app = (*env)->CallStaticObjectMethod(env, at_cls, mid_current_application);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        app = NULL;
    }
    (*env)->DeleteLocalRef(env, at_cls);
    return app;
}

static int get_context_package_name(
        JNIEnv *env,
        jobject context,
        char *out,
        size_t out_cap) {
    if (!context || !out || out_cap < 2) return -1;
    int rc = -1;
    jclass ctx_cls = NULL;
    jstring j_pkg = NULL;
    const char *pkg = NULL;

    ctx_cls = (*env)->GetObjectClass(env, context);
    if (!ctx_cls) goto cleanup;
    jmethodID mid_get_pkg = (*env)->GetMethodID(env, ctx_cls, "getPackageName", "()Ljava/lang/String;");
    if (!mid_get_pkg) goto cleanup;
    j_pkg = (jstring)(*env)->CallObjectMethod(env, context, mid_get_pkg);
    if ((*env)->ExceptionCheck(env) || !j_pkg) goto cleanup;

    pkg = (*env)->GetStringUTFChars(env, j_pkg, NULL);
    if (!pkg) goto cleanup;
    size_t n = strlen(pkg);
    if (n >= out_cap) goto cleanup;
    memcpy(out, pkg, n + 1);
    rc = 0;

cleanup:
    if (pkg) (*env)->ReleaseStringUTFChars(env, j_pkg, pkg);
    if (j_pkg) (*env)->DeleteLocalRef(env, j_pkg);
    if (ctx_cls) (*env)->DeleteLocalRef(env, ctx_cls);
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    return rc;
}

static int get_context_files_dir_path(
        JNIEnv *env,
        jobject context,
        char *out,
        size_t out_cap) {
    if (!context || !out || out_cap < 2) return -1;
    int rc = -1;
    jclass ctx_cls = NULL;
    jobject file_obj = NULL;
    jclass file_cls = NULL;
    jstring j_path = NULL;
    const char *path = NULL;

    ctx_cls = (*env)->GetObjectClass(env, context);
    if (!ctx_cls) goto cleanup;
    jmethodID mid_get_files_dir = (*env)->GetMethodID(env, ctx_cls, "getFilesDir", "()Ljava/io/File;");
    if (!mid_get_files_dir) goto cleanup;
    file_obj = (*env)->CallObjectMethod(env, context, mid_get_files_dir);
    if ((*env)->ExceptionCheck(env) || !file_obj) goto cleanup;

    file_cls = (*env)->GetObjectClass(env, file_obj);
    if (!file_cls) goto cleanup;
    jmethodID mid_get_abs = (*env)->GetMethodID(env, file_cls, "getAbsolutePath", "()Ljava/lang/String;");
    if (!mid_get_abs) goto cleanup;
    j_path = (jstring)(*env)->CallObjectMethod(env, file_obj, mid_get_abs);
    if ((*env)->ExceptionCheck(env) || !j_path) goto cleanup;
    path = (*env)->GetStringUTFChars(env, j_path, NULL);
    if (!path) goto cleanup;

    size_t n = strlen(path);
    if (n >= out_cap) goto cleanup;
    memcpy(out, path, n + 1);
    rc = 0;

cleanup:
    if (path) (*env)->ReleaseStringUTFChars(env, j_path, path);
    if (j_path) (*env)->DeleteLocalRef(env, j_path);
    if (file_cls) (*env)->DeleteLocalRef(env, file_cls);
    if (file_obj) (*env)->DeleteLocalRef(env, file_obj);
    if (ctx_cls) (*env)->DeleteLocalRef(env, ctx_cls);
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    return rc;
}

static int get_context_version_code(
        JNIEnv *env,
        jobject context,
        long long *out_version) {
    if (!context || !out_version) return -1;
    int rc = -1;
    jint sdk_int = 0;
    jclass ctx_cls = NULL;
    jclass pm_cls = NULL;
    jclass version_cls = NULL;
    jclass pi_cls = NULL;
    jobject pm = NULL;
    jobject pi = NULL;
    jstring j_pkg = NULL;

    ctx_cls = (*env)->GetObjectClass(env, context);
    if (!ctx_cls) goto cleanup;
    jmethodID mid_get_pm = (*env)->GetMethodID(env, ctx_cls, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jmethodID mid_get_pkg = (*env)->GetMethodID(env, ctx_cls, "getPackageName", "()Ljava/lang/String;");
    if (!mid_get_pm || !mid_get_pkg) goto cleanup;

    pm = (*env)->CallObjectMethod(env, context, mid_get_pm);
    if ((*env)->ExceptionCheck(env) || !pm) goto cleanup;
    j_pkg = (jstring)(*env)->CallObjectMethod(env, context, mid_get_pkg);
    if ((*env)->ExceptionCheck(env) || !j_pkg) goto cleanup;

    version_cls = (*env)->FindClass(env, "android/os/Build$VERSION");
    if (!version_cls) goto cleanup;
    jfieldID fid_sdk = (*env)->GetStaticFieldID(env, version_cls, "SDK_INT", "I");
    if (!fid_sdk) goto cleanup;
    sdk_int = (*env)->GetStaticIntField(env, version_cls, fid_sdk);
    if ((*env)->ExceptionCheck(env)) goto cleanup;

    pm_cls = (*env)->GetObjectClass(env, pm);
    if (!pm_cls) goto cleanup;
    jmethodID mid_get_pi = (*env)->GetMethodID(
            env,
            pm_cls,
            "getPackageInfo",
            "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    if (!mid_get_pi) goto cleanup;
    pi = (*env)->CallObjectMethod(env, pm, mid_get_pi, j_pkg, 0);
    if ((*env)->ExceptionCheck(env) || !pi) goto cleanup;
    pi_cls = (*env)->GetObjectClass(env, pi);
    if (!pi_cls) goto cleanup;

    if (sdk_int >= 28) {
        jmethodID mid_long_vc = (*env)->GetMethodID(env, pi_cls, "getLongVersionCode", "()J");
        if (!mid_long_vc) goto cleanup;
        jlong lv = (*env)->CallLongMethod(env, pi, mid_long_vc);
        if ((*env)->ExceptionCheck(env)) goto cleanup;
        *out_version = (long long)lv;
    } else {
        jfieldID fid_vc = (*env)->GetFieldID(env, pi_cls, "versionCode", "I");
        if (!fid_vc) goto cleanup;
        jint vc = (*env)->GetIntField(env, pi, fid_vc);
        if ((*env)->ExceptionCheck(env)) goto cleanup;
        *out_version = (long long)vc;
    }
    rc = 0;

cleanup:
    if (pi_cls) (*env)->DeleteLocalRef(env, pi_cls);
    if (pi) (*env)->DeleteLocalRef(env, pi);
    if (pm_cls) (*env)->DeleteLocalRef(env, pm_cls);
    if (version_cls) (*env)->DeleteLocalRef(env, version_cls);
    if (j_pkg) (*env)->DeleteLocalRef(env, j_pkg);
    if (pm) (*env)->DeleteLocalRef(env, pm);
    if (ctx_cls) (*env)->DeleteLocalRef(env, ctx_cls);
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    return rc;
}

static int read_guard_state_file(
        const char *path,
        long long *out_max_ver,
        long long *out_max_epoch,
        char *out_build_id,
        size_t build_id_cap) {
    if (!path || !out_max_ver || !out_max_epoch || !out_build_id || build_id_cap < 2) {
        return -1;
    }
    *out_max_ver = 0;
    *out_max_epoch = 0;
    out_build_id[0] = '\0';

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        return 0;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp) != NULL) {
        trim_ascii_inplace(line);
        if (strncmp(line, "maxVersion=", 11) == 0) {
            long long v = 0;
            if (parse_nonneg_int64(line + 11, &v) == 0) {
                *out_max_ver = v;
            }
        } else if (strncmp(line, "maxEpoch=", 9) == 0) {
            long long v = 0;
            if (parse_nonneg_int64(line + 9, &v) == 0) {
                *out_max_epoch = v;
            }
        } else if (strncmp(line, "maxBuildId=", 11) == 0) {
            const char *src = line + 11;
            size_t n = strlen(src);
            if (n >= build_id_cap) {
                n = build_id_cap - 1;
            }
            memcpy(out_build_id, src, n);
            out_build_id[n] = '\0';
            for (size_t i = 0; out_build_id[i] != '\0'; i++) {
                out_build_id[i] = (char)toupper((unsigned char)out_build_id[i]);
            }
        }
    }
    fclose(fp);
    return 0;
}

static int write_guard_state_file(
        const char *path,
        long long max_ver,
        long long max_epoch,
        const char *max_build_id) {
    if (!path || !max_build_id) return -1;
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        return -1;
    }
    fprintf(fp, "maxVersion=%lld\n", max_ver);
    fprintf(fp, "maxEpoch=%lld\n", max_epoch);
    fprintf(fp, "maxBuildId=%s\n", max_build_id);
    fclose(fp);
    return 0;
}

static int enforce_native_rollback_guard(JNIEnv *env, jobject context) {
    if (!context) return -1;
    if (g_cfg_expect.build_epoch_sec <= 0 &&
        g_cfg_expect.build_version_code <= 0 &&
        g_cfg_expect.build_id[0] == '\0') {
        g_rollback_guard_verified = 1;
        return 0;
    }

    long long current_version = 0;
    if (get_context_version_code(env, context, &current_version) != 0) {
        return -1;
    }
    if (g_cfg_expect.build_version_code > 0 &&
        current_version > 0 &&
        g_cfg_expect.build_version_code != current_version) {
        LOGE("native rollback guard: build version mismatch");
        return -1;
    }

    char files_dir[PATH_MAX];
    char state_path[PATH_MAX];
    memset(files_dir, 0, sizeof(files_dir));
    memset(state_path, 0, sizeof(state_path));
    if (get_context_files_dir_path(env, context, files_dir, sizeof(files_dir)) != 0) {
        return -1;
    }
    if (snprintf(state_path, sizeof(state_path), "%s/.enko_guard_state.bin", files_dir) <= 0) {
        return -1;
    }

    long long max_seen_ver = 0;
    long long max_seen_epoch = 0;
    char max_seen_build_id[65];
    memset(max_seen_build_id, 0, sizeof(max_seen_build_id));
    if (read_guard_state_file(
            state_path,
            &max_seen_ver,
            &max_seen_epoch,
            max_seen_build_id,
            sizeof(max_seen_build_id)) != 0) {
        return -1;
    }

    if (g_cfg_expect.build_version_code > 0 &&
        max_seen_ver > 0 &&
        g_cfg_expect.build_version_code < max_seen_ver) {
        LOGE("native rollback guard: version rollback");
        return -1;
    }
    if (g_cfg_expect.build_epoch_sec > 0 && max_seen_epoch > 0) {
        if (g_cfg_expect.build_epoch_sec < max_seen_epoch) {
            LOGE("native rollback guard: epoch rollback");
            return -1;
        }
    }

    long long new_max_ver = max_seen_ver;
    long long new_max_epoch = max_seen_epoch;
    char new_max_build_id[65];
    memset(new_max_build_id, 0, sizeof(new_max_build_id));
    if (max_seen_build_id[0] != '\0') {
        strncpy(new_max_build_id, max_seen_build_id, sizeof(new_max_build_id) - 1);
    }

    if (g_cfg_expect.build_version_code > new_max_ver) {
        new_max_ver = g_cfg_expect.build_version_code;
        if (g_cfg_expect.build_id[0] != '\0') {
            strncpy(new_max_build_id, g_cfg_expect.build_id, sizeof(new_max_build_id) - 1);
        }
    }
    if (g_cfg_expect.build_epoch_sec > new_max_epoch) {
        new_max_epoch = g_cfg_expect.build_epoch_sec;
        if (g_cfg_expect.build_id[0] != '\0') {
            strncpy(new_max_build_id, g_cfg_expect.build_id, sizeof(new_max_build_id) - 1);
        } else {
            new_max_build_id[0] = '\0';
        }
    } else if (g_cfg_expect.build_epoch_sec == new_max_epoch &&
               new_max_build_id[0] == '\0' &&
               g_cfg_expect.build_id[0] != '\0') {
        strncpy(new_max_build_id, g_cfg_expect.build_id, sizeof(new_max_build_id) - 1);
    }

    if (write_guard_state_file(state_path, new_max_ver, new_max_epoch, new_max_build_id) != 0) {
        return -1;
    }

    g_rollback_guard_verified = 1;
    return 0;
}

static void append_reason(char *buf, size_t cap, const char *reason) {
    if (!buf || !reason || cap < 2) return;
    size_t cur = strlen(buf);
    size_t add = strlen(reason);
    if (cur + add + 2 >= cap) return;
    if (cur > 0) {
        buf[cur++] = ',';
    }
    memcpy(buf + cur, reason, add);
    buf[cur + add] = '\0';
}

static int has_sysprop_proxy(void) {
    char value[PROP_VALUE_MAX];
    memset(value, 0, sizeof(value));
    if (__system_property_get("http.proxyHost", value) > 0 && value[0] != '\0') {
        return 1;
    }
    memset(value, 0, sizeof(value));
    if (__system_property_get("https.proxyHost", value) > 0 && value[0] != '\0') {
        return 1;
    }
    memset(value, 0, sizeof(value));
    if (__system_property_get("socksProxyHost", value) > 0 && value[0] != '\0') {
        return 1;
    }
    return 0;
}

static int has_vpn_interface_native(void) {
    FILE *fp = fopen("/proc/net/dev", "rb");
    if (!fp) {
        return 0;
    }
    char line[512];
    int line_no = 0;
    int found = 0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        line_no++;
        if (line_no <= 2) {
            continue;
        }
        char *colon = strchr(line, ':');
        if (!colon) {
            continue;
        }
        *colon = '\0';
        trim_ascii_inplace(line);
        lowercase_ascii_inplace(line);
        if (strncmp(line, "tun", 3) == 0 ||
            strncmp(line, "ppp", 3) == 0 ||
            strncmp(line, "tap", 3) == 0 ||
            strncmp(line, "utun", 4) == 0 ||
            strncmp(line, "gpd", 3) == 0 ||
            strncmp(line, "ccmni", 5) == 0) {
            found = 1;
            break;
        }
    }
    fclose(fp);
    return found;
}

static int run_native_startup_risk_gate(void) {
    char reasons[512];
    memset(reasons, 0, sizeof(reasons));
    int native_flags = enko_native_detect_risk();
    if ((native_flags & 1) != 0) append_reason(reasons, sizeof(reasons), "native-tracer-detected");
    if ((native_flags & 2) != 0) append_reason(reasons, sizeof(reasons), "native-frida-detected");
    if ((native_flags & 4) != 0) append_reason(reasons, sizeof(reasons), "native-timing-anomaly");
    if ((native_flags & 8) != 0) append_reason(reasons, sizeof(reasons), "native-inline-hook-detected");
    if (g_cfg_expect.detect_root && (native_flags & 16) != 0) {
        append_reason(reasons, sizeof(reasons), "root-environment");
    }
    if (g_cfg_expect.detect_emulator && (native_flags & 32) != 0) {
        append_reason(reasons, sizeof(reasons), "emulator-environment");
    }
    if ((native_flags & 64) != 0) append_reason(reasons, sizeof(reasons), "hook-framework-detected");
    if ((native_flags & 128) != 0) append_reason(reasons, sizeof(reasons), "dump-tool-detected");
    if ((native_flags & 256) != 0) append_reason(reasons, sizeof(reasons), "system-integrity-anomaly");
    if (g_cfg_expect.block_proxy_vpn) {
        if (has_sysprop_proxy()) {
            append_reason(reasons, sizeof(reasons), "native-proxy-detected");
        }
        if (has_vpn_interface_native()) {
            append_reason(reasons, sizeof(reasons), "native-vpn-interface-detected");
        }
    }

    int score = 0;
    int signal_count = 0;
    int high_count = 0;
    int should_block = 0;
    const int block_policy =
            (strcmp(g_cfg_expect.risk_policy, "block") == 0 ||
             strcmp(g_cfg_expect.risk_policy, "degrade") == 0) ? 1 : 0;
    const char *csv = reasons[0] == '\0' ? "" : reasons;
    int rc = enko_native_evaluate_risk(
            g_cfg_expect.risk_profile[0] ? g_cfg_expect.risk_profile : "balanced",
            block_policy,
            csv,
            &score,
            &signal_count,
            &high_count,
            &should_block);
    if (rc != 0) {
        return -1;
    }
    if (should_block) {
        LOGE("native startup risk gate blocked: %s", csv);
        return -1;
    }
    g_startup_risk_verified = 1;
    return 0;
}

static void digest_to_upper_hex(const uint8_t digest[32], char out[65]) {
    static const char HEX[] = "0123456789ABCDEF";
    for (int i = 0; i < 32; i++) {
        out[i * 2] = HEX[(digest[i] >> 4) & 0x0F];
        out[i * 2 + 1] = HEX[digest[i] & 0x0F];
    }
    out[64] = '\0';
}

static int get_current_sign_sha256(
        JNIEnv *env,
        jobject context,
        char out_sha256_hex[65]) {
    if (!context || !out_sha256_hex) return -1;

    int rc = -1;
    jint sdk_int = 0;
    jint pm_flag = 0;

    jclass ctx_cls = NULL;
    jclass pm_cls = NULL;
    jclass pm_obj_cls = NULL;
    jclass version_cls = NULL;
    jclass pi_cls = NULL;
    jclass signing_info_cls = NULL;
    jclass sig_cls = NULL;
    jobject pm = NULL;
    jstring j_pkg = NULL;
    jobject pi = NULL;
    jobject signing_info = NULL;
    jobjectArray sig_arr = NULL;
    jobject sig = NULL;
    jbyteArray cert_bytes = NULL;
    jbyte *cert_ptr = NULL;
    jsize cert_len = 0;

    ctx_cls = (*env)->GetObjectClass(env, context);
    if (!ctx_cls) goto cleanup;
    jmethodID mid_get_pm = (*env)->GetMethodID(env, ctx_cls, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jmethodID mid_get_pkg = (*env)->GetMethodID(env, ctx_cls, "getPackageName", "()Ljava/lang/String;");
    if (!mid_get_pm || !mid_get_pkg) goto cleanup;

    pm = (*env)->CallObjectMethod(env, context, mid_get_pm);
    if ((*env)->ExceptionCheck(env) || !pm) goto cleanup;
    j_pkg = (jstring)(*env)->CallObjectMethod(env, context, mid_get_pkg);
    if ((*env)->ExceptionCheck(env) || !j_pkg) goto cleanup;

    version_cls = (*env)->FindClass(env, "android/os/Build$VERSION");
    if (!version_cls) goto cleanup;
    jfieldID fid_sdk = (*env)->GetStaticFieldID(env, version_cls, "SDK_INT", "I");
    if (!fid_sdk) goto cleanup;
    sdk_int = (*env)->GetStaticIntField(env, version_cls, fid_sdk);
    if ((*env)->ExceptionCheck(env)) goto cleanup;

    pm_cls = (*env)->FindClass(env, "android/content/pm/PackageManager");
    if (!pm_cls) goto cleanup;
    if (sdk_int >= 28) {
        jfieldID fid = (*env)->GetStaticFieldID(env, pm_cls, "GET_SIGNING_CERTIFICATES", "I");
        if (!fid) goto cleanup;
        pm_flag = (*env)->GetStaticIntField(env, pm_cls, fid);
    } else {
        jfieldID fid = (*env)->GetStaticFieldID(env, pm_cls, "GET_SIGNATURES", "I");
        if (!fid) goto cleanup;
        pm_flag = (*env)->GetStaticIntField(env, pm_cls, fid);
    }
    if ((*env)->ExceptionCheck(env)) goto cleanup;

    pm_obj_cls = (*env)->GetObjectClass(env, pm);
    if (!pm_obj_cls) goto cleanup;
    jmethodID mid_get_pi = (*env)->GetMethodID(
            env,
            pm_obj_cls,
            "getPackageInfo",
            "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    if (!mid_get_pi) goto cleanup;

    pi = (*env)->CallObjectMethod(env, pm, mid_get_pi, j_pkg, pm_flag);
    if ((*env)->ExceptionCheck(env) || !pi) goto cleanup;
    pi_cls = (*env)->GetObjectClass(env, pi);
    if (!pi_cls) goto cleanup;

    if (sdk_int >= 28) {
        jfieldID fid_signing_info = (*env)->GetFieldID(
                env,
                pi_cls,
                "signingInfo",
                "Landroid/content/pm/SigningInfo;");
        if (!fid_signing_info) goto cleanup;
        signing_info = (*env)->GetObjectField(env, pi, fid_signing_info);
        if ((*env)->ExceptionCheck(env) || !signing_info) goto cleanup;

        signing_info_cls = (*env)->GetObjectClass(env, signing_info);
        if (!signing_info_cls) goto cleanup;
        jmethodID mid_multi = (*env)->GetMethodID(env, signing_info_cls, "hasMultipleSigners", "()Z");
        jmethodID mid_apk = (*env)->GetMethodID(
                env,
                signing_info_cls,
                "getApkContentsSigners",
                "()[Landroid/content/pm/Signature;");
        jmethodID mid_hist = (*env)->GetMethodID(
                env,
                signing_info_cls,
                "getSigningCertificateHistory",
                "()[Landroid/content/pm/Signature;");
        if (!mid_multi || !mid_apk || !mid_hist) goto cleanup;
        jboolean multi = (*env)->CallBooleanMethod(env, signing_info, mid_multi);
        if ((*env)->ExceptionCheck(env)) goto cleanup;
        sig_arr = (jobjectArray)(*env)->CallObjectMethod(
                env,
                signing_info,
                multi ? mid_apk : mid_hist);
        if ((*env)->ExceptionCheck(env) || !sig_arr) goto cleanup;
    } else {
        jfieldID fid_signatures = (*env)->GetFieldID(
                env,
                pi_cls,
                "signatures",
                "[Landroid/content/pm/Signature;");
        if (!fid_signatures) goto cleanup;
        sig_arr = (jobjectArray)(*env)->GetObjectField(env, pi, fid_signatures);
        if ((*env)->ExceptionCheck(env) || !sig_arr) goto cleanup;
    }

    if ((*env)->GetArrayLength(env, sig_arr) <= 0) goto cleanup;
    sig = (*env)->GetObjectArrayElement(env, sig_arr, 0);
    if (!sig) goto cleanup;
    sig_cls = (*env)->GetObjectClass(env, sig);
    if (!sig_cls) goto cleanup;
    jmethodID mid_to_bytes = (*env)->GetMethodID(env, sig_cls, "toByteArray", "()[B");
    if (!mid_to_bytes) goto cleanup;
    cert_bytes = (jbyteArray)(*env)->CallObjectMethod(env, sig, mid_to_bytes);
    if ((*env)->ExceptionCheck(env) || !cert_bytes) goto cleanup;
    cert_len = (*env)->GetArrayLength(env, cert_bytes);
    if (cert_len <= 0) goto cleanup;
    cert_ptr = (*env)->GetByteArrayElements(env, cert_bytes, NULL);
    if (!cert_ptr) goto cleanup;

    uint8_t digest[32];
    enko_sha256((const uint8_t *)cert_ptr, (size_t)cert_len, digest);
    digest_to_upper_hex(digest, out_sha256_hex);
    enko_secure_wipe(digest, sizeof(digest));
    rc = 0;

cleanup:
    if (cert_ptr && cert_bytes) {
        enko_secure_wipe((uint8_t *)cert_ptr, (size_t)cert_len);
        (*env)->ReleaseByteArrayElements(env, cert_bytes, cert_ptr, JNI_ABORT);
    }
    if (cert_bytes) (*env)->DeleteLocalRef(env, cert_bytes);
    if (sig) (*env)->DeleteLocalRef(env, sig);
    if (sig_arr) (*env)->DeleteLocalRef(env, sig_arr);
    if (signing_info) (*env)->DeleteLocalRef(env, signing_info);
    if (pi) (*env)->DeleteLocalRef(env, pi);
    if (j_pkg) (*env)->DeleteLocalRef(env, j_pkg);
    if (pm) (*env)->DeleteLocalRef(env, pm);
    if (sig_cls) (*env)->DeleteLocalRef(env, sig_cls);
    if (signing_info_cls) (*env)->DeleteLocalRef(env, signing_info_cls);
    if (pi_cls) (*env)->DeleteLocalRef(env, pi_cls);
    if (version_cls) (*env)->DeleteLocalRef(env, version_cls);
    if (pm_obj_cls) (*env)->DeleteLocalRef(env, pm_obj_cls);
    if (pm_cls) (*env)->DeleteLocalRef(env, pm_cls);
    if (ctx_cls) (*env)->DeleteLocalRef(env, ctx_cls);
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    return rc;
}

static int verify_runtime_identity_from_cfg(
        JNIEnv *env,
        jobject context,
        const uint8_t *plain_cfg,
        size_t plain_len) {
    char actual_pkg[256];
    char actual_sha[65];
    int rc = -1;

    memset(actual_pkg, 0, sizeof(actual_pkg));
    memset(actual_sha, 0, sizeof(actual_sha));

    if (load_runtime_expect_from_cfg(plain_cfg, plain_len) != 0) {
        LOGE("cfg parse failed in native");
        goto cleanup;
    }

    if (!context) {
        LOGE("context unavailable in native identity check");
        goto cleanup;
    }
    if (get_context_package_name(env, context, actual_pkg, sizeof(actual_pkg)) != 0) {
        LOGE("cannot read current package name in native");
        goto cleanup;
    }
    if (strcmp(g_cfg_expect.expected_pkg, actual_pkg) != 0) {
        LOGE("package mismatch: expected=%s actual=%s", g_cfg_expect.expected_pkg, actual_pkg);
        goto cleanup;
    }
    if (get_current_sign_sha256(env, context, actual_sha) != 0) {
        LOGE("cannot read current sign sha256 in native");
        goto cleanup;
    }
    if (strcmp(g_cfg_expect.expected_sign_sha256, actual_sha) != 0) {
        LOGE("sign sha256 mismatch");
        goto cleanup;
    }

    rc = 0;

cleanup:
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    return rc;
}

/* ---- Obfuscated detection strings for .init_array ---- */
/* "frida" (len=5) */
OBFSTR_DECL(obs_init_frida, 0xA1,0xB5,0xAE,0xA3,0xA6);
/* "xposed" (len=6) */
OBFSTR_DECL(obs_init_xposed, 0xBF,0xB7,0xA8,0xB4,0xA2,0xA3);
/* "substrate" (len=9) */
OBFSTR_DECL(obs_init_substrate, 0xB4,0xB2,0xA5,0xB4,0xB3,0xB5,0xA6,0xB3,0xA2);
/* "/proc/self/maps" (len=15) */
OBFSTR_DECL(obs_init_maps, 0xE8,0xB7,0xB5,0xA8,0xA4,0xE8,0xB4,0xA2,0xAB,0xA1,0xE8,0xAA,0xA6,0xB7,0xB4);

/* ---- .init_array: runs before JNI_OnLoad, before any Java code ---- */
__attribute__((constructor))
static void enko_preinit(void) {
    /*
     * Earliest possible hook point — before JNI_OnLoad and any Java code.
     * Read /proc/self/maps via raw syscall (bypasses libc hooks) and check
     * for known frida/xposed/substrate .so files already loaded.
     * If detected, _exit() immediately — no Java code has run yet.
     */
    OBFSTR_USE(maps_path, obs_init_maps, 15);
    int fd = (int)syscall(SYS_openat, AT_FDCWD, maps_path, O_RDONLY, 0);
    if (fd < 0) return;

    /* Read maps in chunks — typical maps file is 10-50KB. */
    char buf[4096];
    int leftover = 0;

    /* Decrypt detection keywords onto stack. */
    char kw_frida[6];     obs_init_frida_dec(kw_frida, 5);
    char kw_xposed[7];    obs_init_xposed_dec(kw_xposed, 6);
    char kw_substrate[10]; obs_init_substrate_dec(kw_substrate, 9);

    for (;;) {
        int n = (int)syscall(SYS_read, fd, buf + leftover,
                             (int)sizeof(buf) - leftover - 1);
        if (n <= 0) break;
        int total = leftover + n;
        buf[total] = '\0';

        /* Scan for keywords. */
        if (strstr(buf, kw_frida) || strstr(buf, kw_xposed) ||
            strstr(buf, kw_substrate)) {
            syscall(SYS_close, fd);
            _exit(1);
        }

        /* Keep last 64 bytes to handle keyword split across reads. */
        if (total > 64) {
            memmove(buf, buf + total - 64, 64);
            leftover = 64;
        } else {
            leftover = 0;
        }
    }
    syscall(SYS_close, fd);
}

/* ---- JNI_OnLoad ---- */

#define NATIVE_BRIDGE_CLASS "com/enko/shell/NativeBridge"

static jbyteArray nb_nativeDecrypt(
        JNIEnv *env, jclass clz,
        jbyteArray jEncrypted, jstring jKeyHex);
static jbyteArray nb_nativeDecryptWithEmbeddedKey(
        JNIEnv *env, jclass clz,
        jbyteArray jEncrypted);
static jint nb_nativeDetectRisk(JNIEnv *env, jclass clz);
static jintArray nb_nativeEvaluateRisk(
        JNIEnv *env, jclass clz,
        jstring jRiskProfile, jboolean jBlockPolicy, jstring jReasonsCsv);
static jstring nb_nativeDeobfuscateKey(
        JNIEnv *env, jclass clz,
        jstring jObfuscatedHex);
static jbyteArray nb_nativeGetConfigIntegrityKey(JNIEnv *env, jclass clz);
static jbyteArray nb_nativeDecryptConfig(
        JNIEnv *env, jclass clz,
        jobject context,
        jbyteArray jEncrypted);
static jstring nb_nativeComputeSha256(
        JNIEnv *env, jclass clz,
        jbyteArray jData);
static void nb_nativeAntiDumpInit(JNIEnv *env, jclass clz);
static void nb_nativeMarkNoDump(
        JNIEnv *env, jclass clz,
        jlong address, jint length);
static void nb_nativeWipeMemory(
        JNIEnv *env, jclass clz,
        jlong address, jint length);
static jint nb_nativeDetectDumpTools(JNIEnv *env, jclass clz);
static jint nb_nativeProtectDexRegion(
        JNIEnv *env, jclass clz,
        jlong address, jint length);
static jboolean nb_nativeVerifyApkIntegrity(
        JNIEnv *env, jclass clz,
        jstring jApkPath, jstring jExpectedSha256);
static jboolean nb_nativeVerifyShellDex(
        JNIEnv *env, jclass clz,
        jbyteArray jDexBytes);
static jboolean nb_nativeCommitNativeLibsDigest(
        JNIEnv *env, jclass clz,
        jstring jDigestHex);
static jboolean nb_nativeCommitTrackedLibDigest(
        JNIEnv *env, jclass clz,
        jstring jLibName, jstring jDigestHex);
static jint nb_nativeOpenReadOnly(
        JNIEnv *env, jclass clz,
        jstring jPath);
static jint nb_nativeExtractLoad(
        JNIEnv *env, jclass clz,
        jbyteArray jBlob);
static jint nb_nativeExtractRestore(
        JNIEnv *env, jclass clz,
        jlongArray jAddresses, jintArray jSizes, jint jDexCount);
static jint nb_nativeExtractBindDexBuffers(
        JNIEnv *env, jclass clz,
        jlongArray jAddresses, jintArray jSizes, jint jDexCount);
static jint nb_nativeExtractRestoreClass(
        JNIEnv *env, jclass clz,
        jstring jClassDesc);
static jint nb_nativeD2cRegisterNatives(
        JNIEnv *env, jclass clz,
        jobject jLoader);
static jint nb_nativeVmpLoad(
        JNIEnv *env, jclass clz,
        jbyteArray jBlob);
static jint nb_nativeVmpSetTier(
        JNIEnv *env, jclass clz,
        jint tier);
static jint nb_nativeVmpRegisterNatives(
        JNIEnv *env, jclass clz,
        jobject jLoader);
static jint nb_nativeShellVmpLoad(
        JNIEnv *env, jclass clz,
        jbyteArray jBlob);
static jint nb_nativeShellVmpSetTier(
        JNIEnv *env, jclass clz,
        jint tier);
static jint nb_nativeShellVmpRegisterNatives(
        JNIEnv *env, jclass clz,
        jobject jLoader);

static int register_native_bridge(JNIEnv *env) {
    jclass cls = (*env)->FindClass(env, NATIVE_BRIDGE_CLASS);
    if (!cls) {
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);
        }
        LOGE("FindClass failed: %s", NATIVE_BRIDGE_CLASS);
        return -1;
    }

    static const JNINativeMethod methods[] = {
            {"nativeDecrypt", "([BLjava/lang/String;)[B", (void *)nb_nativeDecrypt},
            {"nativeDecryptWithEmbeddedKey", "([B)[B", (void *)nb_nativeDecryptWithEmbeddedKey},
            {"nativeDecryptConfig", "(Landroid/content/Context;[B)[B", (void *)nb_nativeDecryptConfig},
            {"nativeDetectRisk", "()I", (void *)nb_nativeDetectRisk},
            {"nativeEvaluateRisk", "(Ljava/lang/String;ZLjava/lang/String;)[I", (void *)nb_nativeEvaluateRisk},
            {"nativeDeobfuscateKey", "(Ljava/lang/String;)Ljava/lang/String;", (void *)nb_nativeDeobfuscateKey},
            {"nativeGetConfigIntegrityKey", "()[B", (void *)nb_nativeGetConfigIntegrityKey},
            {"nativeVerifyApkIntegrity", "(Ljava/lang/String;Ljava/lang/String;)Z", (void *)nb_nativeVerifyApkIntegrity},
            {"nativeVerifyShellDex", "([B)Z", (void *)nb_nativeVerifyShellDex},
            {"nativeCommitNativeLibsDigest", "(Ljava/lang/String;)Z", (void *)nb_nativeCommitNativeLibsDigest},
            {"nativeCommitTrackedLibDigest", "(Ljava/lang/String;Ljava/lang/String;)Z", (void *)nb_nativeCommitTrackedLibDigest},
            {"nativeComputeSha256", "([B)Ljava/lang/String;", (void *)nb_nativeComputeSha256},
            {"nativeOpenReadOnly", "(Ljava/lang/String;)I", (void *)nb_nativeOpenReadOnly},
            {"nativeAntiDumpInit", "()V", (void *)nb_nativeAntiDumpInit},
            {"nativeMarkNoDump", "(JI)V", (void *)nb_nativeMarkNoDump},
            {"nativeWipeMemory", "(JI)V", (void *)nb_nativeWipeMemory},
            {"nativeDetectDumpTools", "()I", (void *)nb_nativeDetectDumpTools},
            {"nativeProtectDexRegion", "(JI)I", (void *)nb_nativeProtectDexRegion},
            {"nativeExtractLoad", "([B)I", (void *)nb_nativeExtractLoad},
            {"nativeExtractRestore", "([J[II)I", (void *)nb_nativeExtractRestore},
            {"nativeExtractBindDexBuffers", "([J[II)I", (void *)nb_nativeExtractBindDexBuffers},
            {"nativeExtractRestoreClass", "(Ljava/lang/String;)I", (void *)nb_nativeExtractRestoreClass},
            {"nativeD2cRegisterNatives", "(Ljava/lang/ClassLoader;)I", (void *)nb_nativeD2cRegisterNatives},
            {"nativeVmpLoad", "([B)I", (void *)nb_nativeVmpLoad},
            {"nativeVmpSetTier", "(I)I", (void *)nb_nativeVmpSetTier},
            {"nativeVmpRegisterNatives", "(Ljava/lang/ClassLoader;)I", (void *)nb_nativeVmpRegisterNatives},
            {"nativeShellVmpLoad", "([B)I", (void *)nb_nativeShellVmpLoad},
            {"nativeShellVmpSetTier", "(I)I", (void *)nb_nativeShellVmpSetTier},
            {"nativeShellVmpRegisterNatives", "(Ljava/lang/ClassLoader;)I", (void *)nb_nativeShellVmpRegisterNatives},
    };

    const jint count = (jint)(sizeof(methods) / sizeof(methods[0]));
    const int rc = (*env)->RegisterNatives(env, cls, methods, count);
    (*env)->DeleteLocalRef(env, cls);
    if (rc != 0) {
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);
        }
        LOGE("RegisterNatives failed (%d)", rc);
        return -1;
    }
    return 0;
}

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    JNIEnv *env;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    if (register_native_bridge(env) != 0) {
        return JNI_ERR;
    }

    /* Initialize runtime entropy (build-id + stack canary + .text hash)
     * before any key derivation or thread spawning. */
    enko_key_entropy_init();

    /* Start anti-debug watchdog (ptrace self + background thread). */
    enko_anti_debug_start();

    /* Anti-dump: PR_SET_DUMPABLE=0, fork detection, dump-tool scanner. */
    enko_anti_dump_init();
    reset_runtime_gates();

    LOGI("native library loaded, anti-debug + anti-dump active");

    return JNI_VERSION_1_6;
}

/* ======================================================================
 * com.enko.shell.NativeBridge
 * ====================================================================== */

/*
 * byte[] nativeDecrypt(byte[] encrypted, String keyHex)
 *
 * Decrypts AES-GCM payload entirely in native memory.
 * The key hex is decoded, used, and wiped inside this function —
 * it never lands on the Java heap as raw bytes.
 */
static jbyteArray nb_nativeDecrypt(
        JNIEnv *env, jclass clz,
        jbyteArray jEncrypted, jstring jKeyHex) {
    (void)clz;

    if (!jEncrypted || !jKeyHex) {
        (*env)->ThrowNew(env,
            (*env)->FindClass(env, "java/lang/IllegalArgumentException"),
            "encrypted data and keyHex must not be null");
        return NULL;
    }

    /* ---- Parse key hex ---- */
    const char *keyHexChars = (*env)->GetStringUTFChars(env, jKeyHex, NULL);
    if (!keyHexChars) return NULL;

    size_t hexLen = strlen(keyHexChars);
    uint8_t keyBuf[ENKO_MAX_KEY_LEN];
    int keyBytes = enko_hex_decode(keyHexChars, hexLen, keyBuf, sizeof(keyBuf));
    (*env)->ReleaseStringUTFChars(env, jKeyHex, keyHexChars);

    if (keyBytes < 0) {
        (*env)->ThrowNew(env,
            (*env)->FindClass(env, "java/lang/IllegalArgumentException"),
            "invalid key hex");
        return NULL;
    }

    /* ---- Get encrypted bytes ---- */
    jsize encLen = (*env)->GetArrayLength(env, jEncrypted);
    uint8_t *encBuf = (uint8_t *)malloc((size_t)encLen);
    if (!encBuf) {
        enko_secure_wipe(keyBuf, sizeof(keyBuf));
        (*env)->ThrowNew(env,
            (*env)->FindClass(env, "java/lang/OutOfMemoryError"),
            "native malloc failed");
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, jEncrypted, 0, encLen, (jbyte *)encBuf);

    /* ---- Decrypt ---- */
    size_t plainLen = 0;
    uint8_t *plain = enko_gcm_decrypt(keyBuf, (size_t)keyBytes, encBuf, (size_t)encLen, &plainLen);

    /* Wipe key and encrypted buffer immediately. */
    enko_secure_wipe(keyBuf, sizeof(keyBuf));
    enko_secure_wipe(encBuf, (size_t)encLen);
    free(encBuf);

    if (!plain) {
        (*env)->ThrowNew(env,
            (*env)->FindClass(env, "java/security/GeneralSecurityException"),
            "native AES-GCM decryption failed");
        return NULL;
    }

    /* ---- Return plaintext as jbyteArray ---- */
    jbyteArray result = (*env)->NewByteArray(env, (jsize)plainLen);
    if (result) {
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)plainLen, (const jbyte *)plain);
    }

    /* Wipe and free plaintext. */
    enko_secure_wipe(plain, plainLen);
    free(plain);

    return result;
}

/*
 * byte[] nativeDecryptWithEmbeddedKey(byte[] encrypted)
 *
 * Decrypt payload using the per-APK key (preferred) or the
 * compiled-in derived key (fallback for legacy APKs).
 */
static jbyteArray nb_nativeDecryptWithEmbeddedKey(
        JNIEnv *env, jclass clz,
        jbyteArray jEncrypted) {
    (void)clz;

    if (g_runtime_identity_verified != 1) {
        (*env)->ThrowNew(env,
            (*env)->FindClass(env, "java/lang/SecurityException"),
            "runtime identity not verified");
        return NULL;
    }
    if (g_rollback_guard_verified != 1) {
        (*env)->ThrowNew(env,
            (*env)->FindClass(env, "java/lang/SecurityException"),
            "native rollback guard not verified");
        return NULL;
    }
    if (g_startup_risk_verified != 1) {
        (*env)->ThrowNew(env,
            (*env)->FindClass(env, "java/lang/SecurityException"),
            "native startup risk gate not verified");
        return NULL;
    }
    if (g_cfg_expect.require_shell_dex && g_shell_dex_verified != 1) {
        (*env)->ThrowNew(env,
            (*env)->FindClass(env, "java/lang/SecurityException"),
            "shell dex integrity not verified");
        return NULL;
    }
    if (g_cfg_expect.require_native_libs && g_native_libs_verified != 1) {
        (*env)->ThrowNew(env,
            (*env)->FindClass(env, "java/lang/SecurityException"),
            "native libs integrity not verified");
        return NULL;
    }
    if (g_cfg_expect.require_libapp && g_libapp_verified != 1) {
        (*env)->ThrowNew(env,
            (*env)->FindClass(env, "java/lang/SecurityException"),
            "libapp integrity not verified");
        return NULL;
    }
    if (g_cfg_expect.require_libflutter && g_libflutter_verified != 1) {
        (*env)->ThrowNew(env,
            (*env)->FindClass(env, "java/lang/SecurityException"),
            "libflutter integrity not verified");
        return NULL;
    }

    if (!jEncrypted) {
        (*env)->ThrowNew(env,
            (*env)->FindClass(env, "java/lang/IllegalArgumentException"),
            "encrypted data must not be null");
        return NULL;
    }

    /* Try per-APK random key first; fall back to legacy derived key. */
    uint8_t keyBuf[32];
    int perApkRc = enko_get_per_apk_payload_key(keyBuf);
    if (perApkRc != 0) {
        LOGI("per-apk key not available (rc=%d), using legacy derived key", perApkRc);
        enko_derive_payload_key(keyBuf);
    } else {
        LOGI("using per-apk payload key");
    }

    jsize encLen = (*env)->GetArrayLength(env, jEncrypted);
    uint8_t *encBuf = (uint8_t *)malloc((size_t)encLen);
    if (!encBuf) {
        enko_secure_wipe(keyBuf, sizeof(keyBuf));
        (*env)->ThrowNew(env,
            (*env)->FindClass(env, "java/lang/OutOfMemoryError"),
            "native malloc failed");
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, jEncrypted, 0, encLen, (jbyte *)encBuf);

    size_t plainLen = 0;
    uint8_t *plain = enko_gcm_decrypt(keyBuf, sizeof(keyBuf), encBuf, (size_t)encLen, &plainLen);

    enko_secure_wipe(keyBuf, sizeof(keyBuf));
    enko_secure_wipe(encBuf, (size_t)encLen);
    free(encBuf);

    if (!plain) {
        (*env)->ThrowNew(env,
            (*env)->FindClass(env, "java/security/GeneralSecurityException"),
            "native embedded-key AES-GCM decryption failed");
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, (jsize)plainLen);
    if (result) {
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)plainLen, (const jbyte *)plain);
    }

    enko_secure_wipe(plain, plainLen);
    free(plain);
    return result;
}

/*
 * int nativeDetectRisk()
 *
 * Returns bitmask from enko_native_detect_risk().
 */
static jint nb_nativeDetectRisk(
        JNIEnv *env, jclass clz) {
    (void)env;
    (void)clz;
    return (jint)enko_native_detect_risk();
}

/*
 * int[] nativeEvaluateRisk(String riskProfile, boolean blockPolicy, String reasonsCsv)
 *
 * Returns {score, signalCount, highConfidenceCount, shouldBlockInt}.
 */
static jintArray nb_nativeEvaluateRisk(
        JNIEnv *env, jclass clz,
        jstring jRiskProfile, jboolean jBlockPolicy, jstring jReasonsCsv) {
    (void)clz;

    const char *profile = jRiskProfile
                          ? (*env)->GetStringUTFChars(env, jRiskProfile, NULL)
                          : NULL;
    const char *reasons = jReasonsCsv
                          ? (*env)->GetStringUTFChars(env, jReasonsCsv, NULL)
                          : NULL;

    int score = 0, signal_count = 0, high_count = 0, should_block = 0;
    int rc = enko_native_evaluate_risk(
            profile,
            jBlockPolicy ? 1 : 0,
            reasons,
            &score,
            &signal_count,
            &high_count,
            &should_block);

    if (profile) (*env)->ReleaseStringUTFChars(env, jRiskProfile, profile);
    if (reasons) (*env)->ReleaseStringUTFChars(env, jReasonsCsv, reasons);

    if (rc != 0) {
        return NULL;
    }

    jint out[4];
    out[0] = (jint)score;
    out[1] = (jint)signal_count;
    out[2] = (jint)high_count;
    out[3] = (jint)should_block;

    jintArray result = (*env)->NewIntArray(env, 4);
    if (!result) return NULL;
    (*env)->SetIntArrayRegion(env, result, 0, 4, out);
    return result;
}

/*
 * String nativeDeobfuscateKey(String obfuscatedHex)
 *
 * Takes the XOR-obfuscated key hex from config, deobfuscates it
 * using the compiled-in mask, and returns the real key hex.
 * The real key only exists transiently in native memory.
 */
static jstring nb_nativeDeobfuscateKey(
        JNIEnv *env, jclass clz,
        jstring jObfuscatedHex) {
    (void)clz;

    if (!jObfuscatedHex) {
        (*env)->ThrowNew(env,
            (*env)->FindClass(env, "java/lang/IllegalArgumentException"),
            "obfuscatedHex must not be null");
        return NULL;
    }

    const char *hexChars = (*env)->GetStringUTFChars(env, jObfuscatedHex, NULL);
    if (!hexChars) return NULL;

    size_t hexLen = strlen(hexChars);
    uint8_t seed[ENKO_MAX_KEY_LEN];
    int seedBytes = enko_hex_decode(hexChars, hexLen, seed, sizeof(seed));
    (*env)->ReleaseStringUTFChars(env, jObfuscatedHex, hexChars);

    if (seedBytes < 0) {
        (*env)->ThrowNew(env,
            (*env)->FindClass(env, "java/lang/IllegalArgumentException"),
            "invalid obfuscated key hex");
        return NULL;
    }

    uint8_t realKey[ENKO_MAX_KEY_LEN];
    if (enko_key_deobfuscate(seed, (size_t)seedBytes, realKey, sizeof(realKey)) != 0) {
        enko_secure_wipe(seed, sizeof(seed));
        (*env)->ThrowNew(env,
            (*env)->FindClass(env, "java/lang/IllegalArgumentException"),
            "key deobfuscation failed");
        return NULL;
    }
    enko_secure_wipe(seed, sizeof(seed));

    /* Convert real key to hex string. */
    char hexOut[ENKO_MAX_KEY_LEN * 2 + 1];
    static const char HEX[] = "0123456789ABCDEF";
    for (int i = 0; i < seedBytes; i++) {
        hexOut[i * 2]     = HEX[(realKey[i] >> 4) & 0x0F];
        hexOut[i * 2 + 1] = HEX[realKey[i] & 0x0F];
    }
    hexOut[seedBytes * 2] = '\0';

    enko_secure_wipe(realKey, sizeof(realKey));

    return (*env)->NewStringUTF(env, hexOut);
}

/*
 * byte[] nativeGetConfigIntegrityKey()
 *
 * Derive and return the config integrity key (16 bytes).
 */
static jbyteArray nb_nativeGetConfigIntegrityKey(
        JNIEnv *env, jclass clz) {
    (void)clz;

    uint8_t cfgKey[16];
    enko_derive_cfg_key(cfgKey);

    jbyteArray result = (*env)->NewByteArray(env, 16);
    if (result) {
        (*env)->SetByteArrayRegion(env, result, 0, 16, (const jbyte *)cfgKey);
    }
    enko_secure_wipe(cfgKey, sizeof(cfgKey));
    return result;
}

/* ======================================================================
 * Config decryption
 * ====================================================================== */

/*
 * byte[] nativeDecryptConfig(Context context, byte[] encrypted)
 *
 * Decrypts the AES-GCM encrypted enko_runtime.cfg entirely in native memory.
 * The cfg key is derived from the compiled-in XOR mask — it never appears
 * in the APK or on the Java heap.
 */
static jbyteArray nb_nativeDecryptConfig(
        JNIEnv *env, jclass clz,
        jobject context,
        jbyteArray jEncrypted) {
    (void)clz;
    reset_runtime_gates();

    if (!context || !jEncrypted) {
        (*env)->ThrowNew(env,
            (*env)->FindClass(env, "java/lang/IllegalArgumentException"),
            "context or encrypted config must not be null");
        return NULL;
    }

    /* Derive cfg encryption key from compiled-in mask. */
    uint8_t cfgKey[16];
    enko_derive_cfg_key(cfgKey);

    /* Copy encrypted bytes from Java heap. */
    jsize encLen = (*env)->GetArrayLength(env, jEncrypted);
    uint8_t *encBuf = (uint8_t *)malloc((size_t)encLen);
    if (!encBuf) {
        enko_secure_wipe(cfgKey, sizeof(cfgKey));
        (*env)->ThrowNew(env,
            (*env)->FindClass(env, "java/lang/OutOfMemoryError"),
            "native malloc failed");
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, jEncrypted, 0, encLen, (jbyte *)encBuf);

    /* AES-GCM decrypt with cfg magic. */
    size_t plainLen = 0;
    uint8_t *plain = enko_gcm_decrypt_cfg(cfgKey, 16, encBuf, (size_t)encLen, &plainLen);

    enko_secure_wipe(cfgKey, sizeof(cfgKey));
    enko_secure_wipe(encBuf, (size_t)encLen);
    free(encBuf);

    if (!plain) {
        (*env)->ThrowNew(env,
            (*env)->FindClass(env, "java/security/GeneralSecurityException"),
            "config decryption failed");
        return NULL;
    }

    if (verify_runtime_identity_from_cfg(env, context, plain, plainLen) != 0) {
        enko_secure_wipe(plain, plainLen);
        free(plain);
        (*env)->ThrowNew(env,
            (*env)->FindClass(env, "java/lang/SecurityException"),
            "runtime identity verification failed");
        return NULL;
    }
    /* Propagate risk-policy to the anti-debug watchdog threads. */
    {
        const int blk =
                (strcmp(g_cfg_expect.risk_policy, "block") == 0 ||
                 strcmp(g_cfg_expect.risk_policy, "degrade") == 0) ? 1 : 0;
        enko_anti_debug_set_policy(blk);
    }
    jobject app = (*env)->NewLocalRef(env, context);
    if (!app) {
        enko_secure_wipe(plain, plainLen);
        free(plain);
        (*env)->ThrowNew(env,
            (*env)->FindClass(env, "java/lang/SecurityException"),
            "native context unavailable");
        return NULL;
    }
    if (enforce_native_rollback_guard(env, app) != 0) {
        (*env)->DeleteLocalRef(env, app);
        enko_secure_wipe(plain, plainLen);
        free(plain);
        (*env)->ThrowNew(env,
            (*env)->FindClass(env, "java/lang/SecurityException"),
            "native rollback guard failed");
        return NULL;
    }
    (*env)->DeleteLocalRef(env, app);
    if (run_native_startup_risk_gate() != 0) {
        enko_secure_wipe(plain, plainLen);
        free(plain);
        (*env)->ThrowNew(env,
            (*env)->FindClass(env, "java/lang/SecurityException"),
            "native startup risk blocked");
        return NULL;
    }
    g_runtime_identity_verified = 1;
    if (!g_cfg_expect.require_shell_dex) {
        g_shell_dex_verified = 1;
    }
    if (!g_cfg_expect.require_native_libs) {
        g_native_libs_verified = 1;
    }
    if (!g_cfg_expect.require_libapp) {
        g_libapp_verified = 1;
    }
    if (!g_cfg_expect.require_libflutter) {
        g_libflutter_verified = 1;
    }

    jbyteArray result = (*env)->NewByteArray(env, (jsize)plainLen);
    if (result) {
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)plainLen, (const jbyte *)plain);
    }

    enko_secure_wipe(plain, plainLen);
    free(plain);

    return result;
}

/* ======================================================================
 * SHA-256 utility
 * ====================================================================== */

/*
 * String nativeComputeSha256(byte[] data)
 *
 * Compute SHA-256 of raw bytes in native memory.
 * Returns 64-char uppercase hex string.
 */
static jstring nb_nativeComputeSha256(
        JNIEnv *env, jclass clz,
        jbyteArray jData) {
    (void)clz;

    if (!jData) {
        (*env)->ThrowNew(env,
            (*env)->FindClass(env, "java/lang/IllegalArgumentException"),
            "data must not be null");
        return NULL;
    }

    jsize dataLen = (*env)->GetArrayLength(env, jData);
    uint8_t *buf = (uint8_t *)malloc((size_t)dataLen);
    if (!buf) {
        (*env)->ThrowNew(env,
            (*env)->FindClass(env, "java/lang/OutOfMemoryError"),
            "native malloc failed");
        return NULL;
    }
    (*env)->GetByteArrayRegion(env, jData, 0, dataLen, (jbyte *)buf);

    uint8_t digest[32];
    enko_sha256(buf, (size_t)dataLen, digest);
    enko_secure_wipe(buf, (size_t)dataLen);
    free(buf);

    static const char HEX[] = "0123456789ABCDEF";
    char hex[65];
    for (int i = 0; i < 32; i++) {
        hex[i * 2]     = HEX[(digest[i] >> 4) & 0x0F];
        hex[i * 2 + 1] = HEX[digest[i] & 0x0F];
    }
    hex[64] = '\0';
    enko_secure_wipe(digest, 32);

    return (*env)->NewStringUTF(env, hex);
}

/* ======================================================================
 * Anti-dump JNI methods
 * ====================================================================== */

/*
 * void nativeAntiDumpInit()
 *
 * Re-enforce anti-dump (in case called late or after state reset).
 */
static void nb_nativeAntiDumpInit(
        JNIEnv *env, jclass clz) {
    (void)env;
    (void)clz;
    enko_anti_dump_init();
}

/*
 * void nativeMarkNoDump(long address, int length)
 *
 * Marks a DirectByteBuffer's native memory region as MADV_DONTDUMP
 * so it is excluded from core dumps.
 */
static void nb_nativeMarkNoDump(
        JNIEnv *env, jclass clz,
        jlong address, jint length) {
    (void)env;
    (void)clz;
    if (address != 0 && length > 0) {
        enko_mark_no_dump((void *)(uintptr_t)address, (size_t)length);
    }
}

/*
 * void nativeWipeMemory(long address, int length)
 *
 * Wipe a DirectByteBuffer's native memory (volatile zero-fill + MADV_DONTNEED).
 * Used to destroy DEX content in the ByteBuffer after ClassLoader creation.
 */
static void nb_nativeWipeMemory(
        JNIEnv *env, jclass clz,
        jlong address, jint length) {
    (void)env;
    (void)clz;
    if (address != 0 && length > 0) {
        enko_wipe_memory((void *)(uintptr_t)address, (size_t)length);
    }
}

/*
 * int nativeDetectDumpTools()
 *
 * Returns bitmask: bit 0 = dump tool, bit 1 = memory editor,
 * bit 2 = someone has our /proc/pid/maps or /mem open,
 * bit 3 = suspicious self maps/mem fd leak,
 * bit 4 = coredump_filter not hardened,
 * bit 5 = weak heuristic process match.
 */
static jint nb_nativeDetectDumpTools(
        JNIEnv *env, jclass clz) {
    (void)env;
    (void)clz;
    return (jint)enko_detect_dump_tools();
}

/*
 * int nativeProtectDexRegion(long address, int length)
 *
 * Apply mprotect(PROT_NONE) to a DEX buffer region after ART has loaded it.
 * Blocks /proc/self/mem reads by dump tools.
 */
static jint nb_nativeProtectDexRegion(
        JNIEnv *env, jclass clz,
        jlong address, jint length) {
    (void)env;
    (void)clz;
    if (address == 0 || length <= 0) return -1;
    return (jint)enko_protect_dex_region((void *)(uintptr_t)address, (size_t)length);
}

/* ======================================================================
 * Integrity JNI methods
 * ====================================================================== */

/*
 * boolean nativeVerifyApkIntegrity(String apkPath, String expectedSha256)
 */
static jboolean nb_nativeVerifyApkIntegrity(
        JNIEnv *env, jclass clz,
        jstring jApkPath, jstring jExpectedSha256) {
    (void)clz;

    if (!jApkPath || !jExpectedSha256) return JNI_FALSE;

    const char *path = (*env)->GetStringUTFChars(env, jApkPath, NULL);
    const char *expected = (*env)->GetStringUTFChars(env, jExpectedSha256, NULL);
    if (!path || !expected) {
        if (path) (*env)->ReleaseStringUTFChars(env, jApkPath, path);
        if (expected) (*env)->ReleaseStringUTFChars(env, jExpectedSha256, expected);
        return JNI_FALSE;
    }

    int result = enko_verify_apk_integrity(path, expected);

    (*env)->ReleaseStringUTFChars(env, jApkPath, path);
    (*env)->ReleaseStringUTFChars(env, jExpectedSha256, expected);

    return result == 1 ? JNI_TRUE : JNI_FALSE;
}

/*
 * boolean nativeVerifyShellDex(byte[] dexBytes)
 *
 * Verify shell classes.dex hash against expected value parsed from cfg.
 * Success also opens the shell-dex gate required by payload decryption.
 */
static jboolean nb_nativeVerifyShellDex(
        JNIEnv *env, jclass clz,
        jbyteArray jDexBytes) {
    (void)clz;
    if (!g_cfg_expect.require_shell_dex) {
        g_shell_dex_verified = 1;
        return JNI_TRUE;
    }
    if (!jDexBytes) {
        g_shell_dex_verified = 0;
        return JNI_FALSE;
    }
    jsize len = (*env)->GetArrayLength(env, jDexBytes);
    if (len <= 0) {
        g_shell_dex_verified = 0;
        return JNI_FALSE;
    }
    uint8_t *buf = (uint8_t *)malloc((size_t)len);
    if (!buf) {
        g_shell_dex_verified = 0;
        return JNI_FALSE;
    }
    (*env)->GetByteArrayRegion(env, jDexBytes, 0, len, (jbyte *)buf);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        enko_secure_wipe(buf, (size_t)len);
        free(buf);
        g_shell_dex_verified = 0;
        return JNI_FALSE;
    }
    uint8_t digest[32];
    char hex[65];
    enko_sha256(buf, (size_t)len, digest);
    digest_to_upper_hex(digest, hex);
    enko_secure_wipe(digest, sizeof(digest));
    enko_secure_wipe(buf, (size_t)len);
    free(buf);

    if (strcmp(hex, g_cfg_expect.shell_dex_sha256) == 0) {
        g_shell_dex_verified = 1;
        return JNI_TRUE;
    }
    g_shell_dex_verified = 0;
    return JNI_FALSE;
}

/*
 * boolean nativeCommitNativeLibsDigest(String digestHex)
 *
 * Compare caller-provided aggregate native-libs digest with cfg expected digest.
 * Success opens the native-libs gate required by payload decryption.
 */
static jboolean nb_nativeCommitNativeLibsDigest(
        JNIEnv *env, jclass clz,
        jstring jDigestHex) {
    (void)clz;
    if (!g_cfg_expect.require_native_libs) {
        g_native_libs_verified = 1;
        return JNI_TRUE;
    }
    if (!jDigestHex) {
        g_native_libs_verified = 0;
        return JNI_FALSE;
    }
    const char *chars = (*env)->GetStringUTFChars(env, jDigestHex, NULL);
    if (!chars) {
        g_native_libs_verified = 0;
        return JNI_FALSE;
    }
    char tmp[96];
    memset(tmp, 0, sizeof(tmp));
    size_t n = strlen(chars);
    if (n >= sizeof(tmp)) {
        (*env)->ReleaseStringUTFChars(env, jDigestHex, chars);
        g_native_libs_verified = 0;
        return JNI_FALSE;
    }
    memcpy(tmp, chars, n + 1);
    (*env)->ReleaseStringUTFChars(env, jDigestHex, chars);
    if (normalize_sha256_hex_inplace(tmp) != 0) {
        g_native_libs_verified = 0;
        return JNI_FALSE;
    }
    if (strcmp(tmp, g_cfg_expect.native_libs_sha256) == 0) {
        g_native_libs_verified = 1;
        return JNI_TRUE;
    }
    g_native_libs_verified = 0;
    return JNI_FALSE;
}

/*
 * boolean nativeCommitTrackedLibDigest(String libName, String digestHex)
 *
 * Compare a caller-provided digest for a tracked native library against cfg.
 * Used for Flutter core libraries so payload decryption depends on both file
 * integrity and native gate state.
 */
static jboolean nb_nativeCommitTrackedLibDigest(
        JNIEnv *env, jclass clz,
        jstring jLibName, jstring jDigestHex) {
    (void)clz;
    if (!jLibName || !jDigestHex) {
        g_libapp_verified = 0;
        g_libflutter_verified = 0;
        return JNI_FALSE;
    }

    const char *lib_name = (*env)->GetStringUTFChars(env, jLibName, NULL);
    const char *digest_chars = (*env)->GetStringUTFChars(env, jDigestHex, NULL);
    if (!lib_name || !digest_chars) {
        if (lib_name) {
            (*env)->ReleaseStringUTFChars(env, jLibName, lib_name);
        }
        if (digest_chars) {
            (*env)->ReleaseStringUTFChars(env, jDigestHex, digest_chars);
        }
        g_libapp_verified = 0;
        g_libflutter_verified = 0;
        return JNI_FALSE;
    }

    char tmp[96];
    memset(tmp, 0, sizeof(tmp));
    size_t n = strlen(digest_chars);
    if (n >= sizeof(tmp)) {
        (*env)->ReleaseStringUTFChars(env, jLibName, lib_name);
        (*env)->ReleaseStringUTFChars(env, jDigestHex, digest_chars);
        g_libapp_verified = 0;
        g_libflutter_verified = 0;
        return JNI_FALSE;
    }
    memcpy(tmp, digest_chars, n + 1);
    (*env)->ReleaseStringUTFChars(env, jDigestHex, digest_chars);

    jboolean ok = JNI_FALSE;
    if (normalize_sha256_hex_inplace(tmp) == 0 && strcmp(lib_name, "libapp.so") == 0) {
        if (!g_cfg_expect.require_libapp || strcmp(tmp, g_cfg_expect.libapp_sha256) == 0) {
            g_libapp_verified = 1;
            ok = JNI_TRUE;
        } else {
            g_libapp_verified = 0;
        }
    } else if (normalize_sha256_hex_inplace(tmp) == 0 && strcmp(lib_name, "libflutter.so") == 0) {
        if (!g_cfg_expect.require_libflutter || strcmp(tmp, g_cfg_expect.libflutter_sha256) == 0) {
            g_libflutter_verified = 1;
            ok = JNI_TRUE;
        } else {
            g_libflutter_verified = 0;
        }
    } else {
        g_libapp_verified = 0;
        g_libflutter_verified = 0;
    }

    (*env)->ReleaseStringUTFChars(env, jLibName, lib_name);
    return ok;
}

/*
 * int nativeOpenReadOnly(String path)
 *
 * Open a file with raw syscall(SYS_openat, ...) so user-space libc hooks on
 * open/openat cannot transparently redirect the path.
 *
 * Returns fd (>=0) on success, -1 on failure.
 */
static jint nb_nativeOpenReadOnly(
        JNIEnv *env, jclass clz,
        jstring jPath) {
    (void)clz;
    if (!jPath) {
        return (jint)-1;
    }

    const char *path = (*env)->GetStringUTFChars(env, jPath, NULL);
    if (!path) {
        return (jint)-1;
    }

    int flags = O_RDONLY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    int fd = (int)syscall(SYS_openat, AT_FDCWD, path, flags, 0);

    (*env)->ReleaseStringUTFChars(env, jPath, path);
    return (jint)fd;
}

/* ======================================================================
 * Method Extraction JNI methods
 * ====================================================================== */

/*
 * int nativeExtractLoad(byte[] blob)
 *
 * Decrypt and parse a method extraction blob.
 */
static jint nb_nativeExtractLoad(
        JNIEnv *env, jclass clz,
        jbyteArray jBlob) {
    (void)clz;

    if (!jBlob) {
        LOGE("nativeExtractLoad: blob is null");
        return -1;
    }

    jsize blobLen = (*env)->GetArrayLength(env, jBlob);
    uint8_t *buf = (uint8_t *)malloc((size_t)blobLen);
    if (!buf) {
        LOGE("nativeExtractLoad: malloc failed");
        return -1;
    }
    (*env)->GetByteArrayRegion(env, jBlob, 0, blobLen, (jbyte *)buf);

    int rc = enko_extract_load(buf, (size_t)blobLen);

    enko_secure_wipe(buf, (size_t)blobLen);
    free(buf);
    return (jint)rc;
}

/*
 * int nativeExtractRestore(long[] addresses, int[] sizes, int dexCount)
 *
 * Restore extracted method insns into DirectByteBuffer memory.
 */
static jint nb_nativeExtractRestore(
        JNIEnv *env, jclass clz,
        jlongArray jAddresses, jintArray jSizes, jint jDexCount) {
    (void)clz;

    if (!jAddresses || !jSizes || jDexCount <= 0) {
        LOGE("nativeExtractRestore: invalid args");
        return -1;
    }

    int count = (int)jDexCount;
    jlong *addrs = (*env)->GetLongArrayElements(env, jAddresses, NULL);
    jint  *sizes = (*env)->GetIntArrayElements(env, jSizes, NULL);
    if (!addrs || !sizes) {
        if (addrs) (*env)->ReleaseLongArrayElements(env, jAddresses, addrs, 0);
        if (sizes) (*env)->ReleaseIntArrayElements(env, jSizes, sizes, 0);
        return -1;
    }

    uintptr_t *native_addrs = (uintptr_t *)malloc(sizeof(uintptr_t) * count);
    int32_t   *native_sizes = (int32_t *)malloc(sizeof(int32_t) * count);
    if (!native_addrs || !native_sizes) {
        free(native_addrs);
        free(native_sizes);
        (*env)->ReleaseLongArrayElements(env, jAddresses, addrs, 0);
        (*env)->ReleaseIntArrayElements(env, jSizes, sizes, 0);
        return -1;
    }

    for (int i = 0; i < count; i++) {
        native_addrs[i] = (uintptr_t)addrs[i];
        native_sizes[i] = (int32_t)sizes[i];
    }

    (*env)->ReleaseLongArrayElements(env, jAddresses, addrs, 0);
    (*env)->ReleaseIntArrayElements(env, jSizes, sizes, 0);

    int rc = enko_extract_restore(native_addrs, native_sizes, count);

    free(native_addrs);
    free(native_sizes);
    return (jint)rc;
}

/*
 * int nativeExtractBindDexBuffers(long[] addresses, int[] sizes, int dexCount)
 *
 * Bind DEX DirectByteBuffer addresses so the extraction runtime can
 * restore method insns on-demand per class.
 */
static jint nb_nativeExtractBindDexBuffers(
        JNIEnv *env, jclass clz,
        jlongArray jAddresses, jintArray jSizes, jint jDexCount) {
    (void)clz;

    if (!jAddresses || !jSizes || jDexCount <= 0) {
        LOGE("nativeExtractBindDexBuffers: invalid args");
        return -1;
    }

    int count = (int)jDexCount;
    jlong *addrs = (*env)->GetLongArrayElements(env, jAddresses, NULL);
    jint  *sizes = (*env)->GetIntArrayElements(env, jSizes, NULL);
    if (!addrs || !sizes) {
        if (addrs) (*env)->ReleaseLongArrayElements(env, jAddresses, addrs, 0);
        if (sizes) (*env)->ReleaseIntArrayElements(env, jSizes, sizes, 0);
        return -1;
    }

    uintptr_t *native_addrs = (uintptr_t *)malloc(sizeof(uintptr_t) * count);
    int32_t   *native_sizes = (int32_t *)malloc(sizeof(int32_t) * count);
    if (!native_addrs || !native_sizes) {
        free(native_addrs);
        free(native_sizes);
        (*env)->ReleaseLongArrayElements(env, jAddresses, addrs, 0);
        (*env)->ReleaseIntArrayElements(env, jSizes, sizes, 0);
        return -1;
    }

    for (int i = 0; i < count; i++) {
        native_addrs[i] = (uintptr_t)addrs[i];
        native_sizes[i] = (int32_t)sizes[i];
    }

    (*env)->ReleaseLongArrayElements(env, jAddresses, addrs, 0);
    (*env)->ReleaseIntArrayElements(env, jSizes, sizes, 0);

    int rc = enko_extract_bind_dex_buffers(native_addrs, native_sizes, count);

    free(native_addrs);
    free(native_sizes);
    return (jint)rc;
}

/*
 * int nativeExtractRestoreClass(String classDesc)
 *
 * Restore extracted method insns for a single class (on-demand).
 */
static jint nb_nativeExtractRestoreClass(
        JNIEnv *env, jclass clz,
        jstring jClassDesc) {
    (void)clz;

    if (!jClassDesc) {
        LOGE("nativeExtractRestoreClass: classDesc is null");
        return -1;
    }

    const char *desc = (*env)->GetStringUTFChars(env, jClassDesc, NULL);
    if (!desc) return -1;

    int rc = enko_extract_restore_class(desc);

    (*env)->ReleaseStringUTFChars(env, jClassDesc, desc);
    return (jint)rc;
}

/* ======================================================================
 * DEX2C JNI methods
 * ====================================================================== */

/*
 * int nativeD2cRegisterNatives(ClassLoader loader)
 *
 * Opens libagpjnix.so via dlopen, resolves enko_d2c_init, and calls
 * it to register all DEX2C-compiled native methods.
 */
static jint nb_nativeD2cRegisterNatives(
        JNIEnv *env, jclass clz,
        jobject jLoader) {
    (void)clz;

    if (!jLoader) {
        LOGE("nativeD2cRegisterNatives: loader is null");
        return -1;
    }

    /* dlopen libagpjnix.so — it should already be loaded via
     * System.loadLibrary("agpjnix") from Java, so RTLD_NOLOAD
     * is tried first for efficiency, with a full load as fallback. */
    void *handle = dlopen("libagpjnix.so", RTLD_NOW | RTLD_NOLOAD);
    if (!handle) {
        handle = dlopen("libagpjnix.so", RTLD_NOW);
    }
    if (!handle) {
        LOGE("nativeD2cRegisterNatives: dlopen failed: %s", dlerror());
        return -1;
    }

    typedef int (*d2c_init_fn)(JNIEnv *, jobject);
    d2c_init_fn init_fn = (d2c_init_fn)dlsym(handle, "enko_d2c_init");
    if (!init_fn) {
        LOGE("nativeD2cRegisterNatives: dlsym failed: %s", dlerror());
        dlclose(handle);
        return -1;
    }

    int rc = init_fn(env, jLoader);
    LOGI("DEX2C: enko_d2c_init registered %d method(s)", rc);

    /* Don't dlclose — the registered native methods point into this .so. */
    return (jint)rc;
}

/* ======================================================================
 * VMP JNI methods
 * ====================================================================== */

/*
 * int nativeVmpLoad(byte[] blob)
 *
 * Parse a VMP bytecode blob into the native interpreter context.
 */
static jint nb_nativeVmpLoad(
        JNIEnv *env, jclass clz,
        jbyteArray jBlob) {
    (void)clz;

    if (!jBlob) {
        LOGE("nativeVmpLoad: blob is null");
        return -1;
    }

    jsize blobLen = (*env)->GetArrayLength(env, jBlob);
    uint8_t *buf = (uint8_t *)malloc((size_t)blobLen);
    if (!buf) {
        LOGE("nativeVmpLoad: malloc failed");
        return -1;
    }
    (*env)->GetByteArrayRegion(env, jBlob, 0, blobLen, (jbyte *)buf);

    int rc = enko_vmp_load(buf, (size_t)blobLen);

    /* Wipe and free the blob copy — the interpreter made its own copies. */
    enko_secure_wipe(buf, (size_t)blobLen);
    free(buf);

    if (rc != 0) {
        LOGE("nativeVmpLoad: enko_vmp_load failed");
    } else {
        LOGI("VMP blob loaded successfully");
    }
    return (jint)rc;
}

/*
 * int nativeVmpSetTier(int tier)
 *
 * Select the payload VMP interpreter core profile.
 */
static jint nb_nativeVmpSetTier(
        JNIEnv *env, jclass clz,
        jint tier) {
    (void)env;
    (void)clz;
    return (jint)enko_vmp_set_tier((int)tier);
}

/*
 * int nativeVmpRegisterNatives(ClassLoader loader)
 *
 * Register JNI native methods for all VMP-protected methods.
 */
static jint nb_nativeVmpRegisterNatives(
        JNIEnv *env, jclass clz,
        jobject jLoader) {
    (void)clz;

    if (!jLoader) {
        LOGE("nativeVmpRegisterNatives: loader is null");
        return -1;
    }

    int rc = enko_vmp_register_natives(env, jLoader);
    if (rc < 0) {
        LOGE("nativeVmpRegisterNatives: failed");
    } else {
        LOGI("VMP registered %d native method(s)", rc);
    }
    return (jint)rc;
}

/*
 * int nativeShellVmpLoad(byte[] blob)
 *
 * Parse a shell VMP bytecode blob into the shell interpreter context.
 */
static jint nb_nativeShellVmpLoad(
        JNIEnv *env, jclass clz,
        jbyteArray jBlob) {
    (void)clz;

    if (!jBlob) {
        LOGE("nativeShellVmpLoad: blob is null");
        return -1;
    }

    jsize blobLen = (*env)->GetArrayLength(env, jBlob);
    uint8_t *buf = (uint8_t *)malloc((size_t)blobLen);
    if (!buf) {
        LOGE("nativeShellVmpLoad: malloc failed");
        return -1;
    }
    (*env)->GetByteArrayRegion(env, jBlob, 0, blobLen, (jbyte *)buf);

    int rc = enko_vmp_shell_load(buf, (size_t)blobLen);

    enko_secure_wipe(buf, (size_t)blobLen);
    free(buf);

    if (rc != 0) {
        LOGE("nativeShellVmpLoad: enko_vmp_shell_load failed");
    } else {
        LOGI("shell VMP blob loaded successfully");
    }
    return (jint)rc;
}

/*
 * int nativeShellVmpSetTier(int tier)
 *
 * Select the shell VMP interpreter core profile.
 */
static jint nb_nativeShellVmpSetTier(
        JNIEnv *env, jclass clz,
        jint tier) {
    (void)env;
    (void)clz;
    return (jint)enko_vmp_shell_set_tier((int)tier);
}

/*
 * int nativeShellVmpRegisterNatives(ClassLoader loader)
 *
 * Register JNI native methods for all shell VMP-protected methods.
 */
static jint nb_nativeShellVmpRegisterNatives(
        JNIEnv *env, jclass clz,
        jobject jLoader) {
    (void)clz;

    if (!jLoader) {
        LOGE("nativeShellVmpRegisterNatives: loader is null");
        return -1;
    }

    int rc = enko_vmp_shell_register_natives(env, jLoader);
    if (rc < 0) {
        LOGE("nativeShellVmpRegisterNatives: failed");
    } else {
        LOGI("shell VMP registered %d native method(s)", rc);
    }
    return (jint)rc;
}
