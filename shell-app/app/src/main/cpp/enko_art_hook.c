/*
 * enko_art_hook.c — minimal ART method hook (Android 9 only)
 *
 * Patches ContextWrapper.attachBaseContext so that re-attaching a Context
 * is a no-op (no IllegalStateException). This works around the Android 9
 * specific SIGSEGV at ContextWrapper.getApplicationInfo+53 that fires
 * during AppCompatActivity launch in our hardened processes: the
 * framework hits a code path that touches Activity.mBase before
 * Activity.attach() finishes setting it, and there's no Java-side hook
 * to either prevent the touch or the "Base context already set" check
 * — only by replacing the method body itself.
 *
 * Strategy ("native rewrite" hook):
 *   1. Resolve ContextWrapper.attachBaseContext via JNI (jmethodID).
 *      On Android 8+ the jmethodID IS the ArtMethod* pointer.
 *   2. Patch access_flags_ to add ACC_NATIVE (0x100).
 *   3. RegisterNatives binds our C function as the new body.
 *   4. ART's normal dispatch will route every call through our C
 *      function, which just writes mBase via reflection — without
 *      the IllegalStateException check.
 *
 * Caveats (acknowledged):
 *   - ArtMethod struct layout is API-level- and ABI-specific. We only
 *     ship the Android 9 (API 28) layout for now. Other versions just
 *     no-op (the hook is best-effort and the existing SIGSEGV
 *     reappears, so AppCompatActivity-based apps on those versions
 *     still need attention).
 *   - We don't preserve / restore the original method body. That's
 *     intentional — re-attach-as-no-op is exactly what we want. The
 *     framework only ever calls attachBaseContext once per
 *     ContextWrapper in normal flow, so suppressing the second-call
 *     check has no observable effect when the flow is correct, and
 *     unblocks the rare path where a wrapper-replacement framework
 *     (like ours) needs the field re-settable.
 */

#include <jni.h>
#include <android/log.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/system_properties.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TAG "EnkoArtHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* ArtMethod field offsets (in BYTES from struct start). x86_64 layouts. */
typedef struct {
    int sdk_int;
    size_t access_flags_off;
    size_t entry_point_off;
} art_method_layout_t;

/* Android 9 (API 28) ArtMethod, x86_64:
 *   GcRoot<Class>             declaring_class_       offset 0  (4 bytes)
 *   atomic<uint32_t>          access_flags_          offset 4
 *   uint32_t                  dex_code_item_offset_  offset 8
 *   uint32_t                  dex_method_index_      offset 12
 *   uint16_t                  method_index_          offset 16
 *   uint16_t                  hotness_count_         offset 18
 *   struct {
 *       void* dex_cache_resolved_methods_;           offset 20
 *       void* data_;                                 offset 28
 *       void* entry_point_from_quick_compiled_code_; offset 36
 *   }
 */
static art_method_layout_t pick_layout(void) {
    art_method_layout_t l = { .sdk_int = 0, .access_flags_off = 4,
                              .entry_point_off = 0 };

    char value[PROP_VALUE_MAX] = {0};
    __system_property_get("ro.build.version.sdk", value);
    l.sdk_int = atoi(value);

    /* access_flags_ has been at offset 4 from at least API 26 through API
     * 34 on x86_64 / arm64. entry_point shifts with ABI: on 64-bit the
     * PtrSizedFields trail at offsets that depend on whether dex_cache_
     * resolved_methods_ is still present (removed in API 27, restored
     * in some 28 builds). For Android 9 (API 28) x86_64 the
     * entry_point_from_quick_compiled_code_ is at offset 32 (after
     * data_ at offset 24 — and dex_cache_resolved_methods_ was
     * removed by the time Pie shipped). */
    if (l.sdk_int >= 28) {
        l.entry_point_off = 32;  /* api 28+ x86_64 / arm64 */
    } else if (l.sdk_int >= 26) {
        l.entry_point_off = 40;  /* api 26-27, when dex_cache_resolved_methods_ was still present */
    }
    return l;
}

/* ACC_NATIVE bit per dex spec — applies in ArtMethod access_flags_. */
#define ENKO_ART_ACC_NATIVE 0x0100

/* Make the page containing the ArtMethod writable and KEEP IT writable
 * through the subsequent RegisterNatives call (which writes data_ /
 * entry_point_from_jni_ fields at later offsets in the same struct).
 * Caller passes the artmethod pointer to compute the right page. */
static int unprotect_artmethod_page(uintptr_t artm) {
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    /* Cover both the ArtMethod start and 64 bytes past it — ArtMethod is
     * ~44 bytes on x86_64 but might straddle a page boundary near the
     * end. mprotect with two pages handles the straddle case. */
    void *page_start = (void *)(artm & ~(page - 1));
    if (mprotect(page_start, page * 2, PROT_READ | PROT_WRITE) != 0) {
        LOGW("mprotect failed for ArtMethod page %p (errno=%d)",
             page_start, errno);
        return -1;
    }
    return 0;
}

static int set_method_native(jmethodID mid) {
    if (!mid) return -1;
    art_method_layout_t l = pick_layout();
    if (l.sdk_int < 26) {
        LOGW("set_method_native: SDK %d not supported (need >=26)", l.sdk_int);
        return -1;
    }

    /* jmethodID === ArtMethod* on Android 8+ ART (well documented in
     * ART source: art/runtime/jni/jni_internal.cc EncodeArtMethod). */
    uintptr_t artm = (uintptr_t)mid;
    _Atomic uint32_t *flags_ptr = (_Atomic uint32_t *)(artm + l.access_flags_off);

    /* Make the page RW and LEAVE IT THAT WAY. The subsequent
     * RegisterNatives call writes ArtMethod.data_ and the entry point
     * field at later offsets; if we restore PROT_READ between the flag
     * set and RegisterNatives, libart segfaults on the data_ write. We
     * accept leaving the page RW for the lifetime of the process —
     * it's a known trade-off for ART hooking, made by every existing
     * runtime hook framework (Pine, FastHook, YAHFA, Substrate). */
    if (unprotect_artmethod_page(artm) != 0) {
        /* Some ART builds keep ArtMethod pages RW by default; carry on
         * and let the atomic OR succeed or fault — either way we tried. */
    }

    uint32_t prev = atomic_load_explicit(flags_ptr, memory_order_acquire);
    if (prev & ENKO_ART_ACC_NATIVE) {
        LOGI("method already native (flags=0x%x); skipping flag set", prev);
    } else {
        atomic_fetch_or_explicit(flags_ptr, ENKO_ART_ACC_NATIVE,
                                 memory_order_acq_rel);
        LOGI("set ACC_NATIVE on ArtMethod (was=0x%x, now=0x%x)",
             prev, prev | ENKO_ART_ACC_NATIVE);
    }
    return 0;
}

/*
 * Replacement implementation for ContextWrapper.attachBaseContext.
 *
 * Original:
 *   protected void attachBaseContext(Context base) {
 *       if (mBase != null) throw new IllegalStateException("Base context already set");
 *       mBase = base;
 *   }
 *
 * Ours:
 *   protected void attachBaseContext(Context base) {
 *       mBase = base;
 *   }
 *
 * The framework only legitimately calls attachBaseContext once per
 * wrapper, so removing the redundant-attach guard doesn't affect normal
 * flow. It just permits our shell to pre-seed mBase early to keep
 * AppCompat's attachBaseContext path (which reads activity.mBase
 * indirectly) from hitting a null deref on Android 9.
 */
JNIEXPORT void JNICALL enko_ctxwrapper_attachBaseContext(
        JNIEnv *env, jobject self, jobject base) {
    static jfieldID g_mBaseField = NULL;

    if (!g_mBaseField) {
        jclass cw = (*env)->FindClass(env, "android/content/ContextWrapper");
        if (!cw) {
            LOGE("could not resolve ContextWrapper class");
            return;
        }
        g_mBaseField = (*env)->GetFieldID(
                env, cw, "mBase", "Landroid/content/Context;");
        (*env)->DeleteLocalRef(env, cw);
        if (!g_mBaseField) {
            LOGE("could not resolve ContextWrapper.mBase field");
            return;
        }
    }

    /* Unconditionally set mBase. No IllegalStateException. */
    (*env)->SetObjectField(env, self, g_mBaseField, base);
}

/*
 * Replacement for ContextWrapper.getApplicationInfo.
 *
 * Original:
 *   public ApplicationInfo getApplicationInfo() {
 *       return mBase.getApplicationInfo();
 *   }
 *
 * Ours: null-safe. When mBase is null (the activity-attached-too-early
 * window on Android 9), return the running Application's ApplicationInfo
 * instead of crashing.
 */
/* Generic fall-through helper: if mBase is null, return result of
 * calling `method_name(sig)` on the current Application. Otherwise
 * delegate to mBase. */
static jobject g_currentAppCache = NULL;  /* GlobalRef cache */
static jclass g_appThreadClass = NULL;
static jmethodID g_appCurrentMid = NULL;
static jfieldID g_ctxWrapperMBaseField = NULL;
static jclass g_ctxClass = NULL;
static jmethodID g_ctxGetApplicationInfo = NULL;
static jmethodID g_ctxGetPackageName = NULL;
static jmethodID g_ctxGetResources = NULL;
static jmethodID g_ctxGetPackageManager = NULL;
static jmethodID g_ctxGetTheme = NULL;
static jmethodID g_ctxGetClassLoader = NULL;
static jmethodID g_ctxGetApplicationContext = NULL;
static jmethodID g_ctxGetAssets = NULL;
static jmethodID g_ctxGetContentResolver = NULL;
static jmethodID g_ctxGetSystemServiceStr = NULL;
static jmethodID g_ctxGetString = NULL;

static void ensure_hook_cache(JNIEnv *env) {
    if (g_ctxWrapperMBaseField) return;
    jclass cw = (*env)->FindClass(env, "android/content/ContextWrapper");
    g_ctxWrapperMBaseField = (*env)->GetFieldID(env, cw, "mBase",
            "Landroid/content/Context;");
    (*env)->DeleteLocalRef(env, cw);

    jclass ctx = (*env)->FindClass(env, "android/content/Context");
    g_ctxClass = (jclass)(*env)->NewGlobalRef(env, ctx);
    g_ctxGetApplicationInfo = (*env)->GetMethodID(env, ctx, "getApplicationInfo",
            "()Landroid/content/pm/ApplicationInfo;");
    g_ctxGetPackageName = (*env)->GetMethodID(env, ctx, "getPackageName",
            "()Ljava/lang/String;");
    g_ctxGetResources = (*env)->GetMethodID(env, ctx, "getResources",
            "()Landroid/content/res/Resources;");
    g_ctxGetPackageManager = (*env)->GetMethodID(env, ctx, "getPackageManager",
            "()Landroid/content/pm/PackageManager;");
    g_ctxGetTheme = (*env)->GetMethodID(env, ctx, "getTheme",
            "()Landroid/content/res/Resources$Theme;");
    g_ctxGetClassLoader = (*env)->GetMethodID(env, ctx, "getClassLoader",
            "()Ljava/lang/ClassLoader;");
    g_ctxGetApplicationContext = (*env)->GetMethodID(env, ctx,
            "getApplicationContext", "()Landroid/content/Context;");
    g_ctxGetAssets = (*env)->GetMethodID(env, ctx, "getAssets",
            "()Landroid/content/res/AssetManager;");
    g_ctxGetContentResolver = (*env)->GetMethodID(env, ctx, "getContentResolver",
            "()Landroid/content/ContentResolver;");
    g_ctxGetSystemServiceStr = (*env)->GetMethodID(env, ctx, "getSystemService",
            "(Ljava/lang/String;)Ljava/lang/Object;");
    g_ctxGetString = (*env)->GetMethodID(env, ctx, "getString",
            "(I)Ljava/lang/String;");
    (*env)->DeleteLocalRef(env, ctx);

    jclass at = (*env)->FindClass(env, "android/app/ActivityThread");
    g_appThreadClass = (jclass)(*env)->NewGlobalRef(env, at);
    g_appCurrentMid = (*env)->GetStaticMethodID(env, at,
            "currentApplication", "()Landroid/app/Application;");
    (*env)->DeleteLocalRef(env, at);
}

static jobject get_running_app(JNIEnv *env) {
    if (!g_appThreadClass) return NULL;
    return (*env)->CallStaticObjectMethod(env,
            g_appThreadClass, g_appCurrentMid);
}

/* Replacements: read mBase, delegate if non-null, else fall back to running
 * Application. Each returns the appropriate type for the original method. */

/* Macro to define a thin null-safe wrapper that delegates to mBase if
 * present, else to the running Application. Used to replace every
 * ContextWrapper accessor that the framework AOT may call on a
 * partially-attached Activity. */
#define DEFINE_CTX_OBJ_HOOK(name, mid_var)                                  \
    JNIEXPORT jobject JNICALL enko_ctxwrapper_##name(                       \
            JNIEnv *env, jobject self) {                                    \
        ensure_hook_cache(env);                                             \
        jobject mBase = (*env)->GetObjectField(env, self,                   \
                g_ctxWrapperMBaseField);                                    \
        if (mBase) {                                                        \
            jobject r = (*env)->CallObjectMethod(env, mBase, mid_var);      \
            (*env)->DeleteLocalRef(env, mBase);                             \
            return r;                                                       \
        }                                                                   \
        jobject app = get_running_app(env);                                 \
        if (!app) return NULL;                                              \
        jobject r = (*env)->CallObjectMethod(env, app, mid_var);            \
        (*env)->DeleteLocalRef(env, app);                                   \
        return r;                                                           \
    }

DEFINE_CTX_OBJ_HOOK(getApplicationInfo, g_ctxGetApplicationInfo)
DEFINE_CTX_OBJ_HOOK(getPackageName, g_ctxGetPackageName)
DEFINE_CTX_OBJ_HOOK(getResources, g_ctxGetResources)
DEFINE_CTX_OBJ_HOOK(getPackageManager, g_ctxGetPackageManager)
DEFINE_CTX_OBJ_HOOK(getTheme, g_ctxGetTheme)
DEFINE_CTX_OBJ_HOOK(getClassLoader, g_ctxGetClassLoader)
DEFINE_CTX_OBJ_HOOK(getApplicationContext, g_ctxGetApplicationContext)
DEFINE_CTX_OBJ_HOOK(getAssets, g_ctxGetAssets)
DEFINE_CTX_OBJ_HOOK(getContentResolver, g_ctxGetContentResolver)

/* Borrow the JNI trampoline entry-point from an existing native method.
 * Every Java native method's ArtMethod.entry_point_from_quick_compiled_code_
 * points at art_quick_generic_jni_trampoline (or art_quick_to_interpreter
 * for non-AOT'd ones — both work for our purpose since the ACC_NATIVE
 * dispatch goes through them to look up the RegisterNatives binding).
 * Object.notify is native, present on every Android version, in
 * boot-image so its entry point is a stable trampoline. */
static void *fetch_jni_trampoline(JNIEnv *env, art_method_layout_t *l) {
    if (l->entry_point_off == 0) return NULL;

    jclass obj = (*env)->FindClass(env, "java/lang/Object");
    if (!obj) return NULL;
    jmethodID notify = (*env)->GetMethodID(env, obj, "notify", "()V");
    (*env)->DeleteLocalRef(env, obj);
    if (!notify) return NULL;

    void *entry = *(void **)((uintptr_t)notify + l->entry_point_off);
    LOGI("borrowed JNI trampoline from Object.notify: %p", entry);
    return entry;
}

static int redirect_to_jni_trampoline(jmethodID mid, void *trampoline,
                                       art_method_layout_t *l) {
    if (!trampoline || l->entry_point_off == 0) return -1;
    void **slot = (void **)((uintptr_t)mid + l->entry_point_off);
    /* Page should already be RW from set_method_native. */
    *slot = trampoline;
    LOGI("patched entry_point_from_quick_compiled_code at +%zu = %p",
         l->entry_point_off, trampoline);
    return 0;
}

/**
 * Install the ContextWrapper.attachBaseContext hook. Call once from
 * ProxyApplication.attachBaseContext (earliest safe Java entry).
 *
 * Returns 0 on success, -1 on failure. On failure the original method
 * stays in place — the SIGSEGV will return for AppCompat apps on
 * Android 9 but no other regression occurs.
 */
int enko_art_hook_install_ctxwrapper(JNIEnv *env) {
    jclass cw = (*env)->FindClass(env, "android/content/ContextWrapper");
    if (!cw) {
        LOGE("FindClass(ContextWrapper) failed");
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        return -1;
    }

    jmethodID mid = (*env)->GetMethodID(
            env, cw, "attachBaseContext", "(Landroid/content/Context;)V");
    if (!mid) {
        LOGE("GetMethodID(attachBaseContext) failed");
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, cw);
        return -1;
    }

    if (set_method_native(mid) != 0) {
        LOGE("set_method_native failed");
        (*env)->DeleteLocalRef(env, cw);
        return -1;
    }

    ensure_hook_cache(env);

    /* Pull all the methods we want to hook, set ACC_NATIVE on each, and
     * patch their entry_point_from_quick_compiled_code_ to point at a
     * borrowed JNI trampoline so AOT-direct callers reach our JNI
     * binding instead of executing the original AOT'd body. */
    art_method_layout_t layout = pick_layout();
    void *trampoline = fetch_jni_trampoline(env, &layout);
    if (!trampoline) {
        LOGE("could not borrow JNI trampoline — bailing");
        (*env)->DeleteLocalRef(env, cw);
        return -1;
    }

    struct hook_target {
        const char *name;
        const char *sig;
        void *impl;
    };
    struct hook_target targets[] = {
        { "attachBaseContext", "(Landroid/content/Context;)V",
          (void *)enko_ctxwrapper_attachBaseContext },
        { "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;",
          (void *)enko_ctxwrapper_getApplicationInfo },
        { "getPackageName", "()Ljava/lang/String;",
          (void *)enko_ctxwrapper_getPackageName },
        { "getResources", "()Landroid/content/res/Resources;",
          (void *)enko_ctxwrapper_getResources },
        { "getPackageManager", "()Landroid/content/pm/PackageManager;",
          (void *)enko_ctxwrapper_getPackageManager },
        { "getTheme", "()Landroid/content/res/Resources$Theme;",
          (void *)enko_ctxwrapper_getTheme },
        { "getClassLoader", "()Ljava/lang/ClassLoader;",
          (void *)enko_ctxwrapper_getClassLoader },
        { "getApplicationContext", "()Landroid/content/Context;",
          (void *)enko_ctxwrapper_getApplicationContext },
        { "getAssets", "()Landroid/content/res/AssetManager;",
          (void *)enko_ctxwrapper_getAssets },
        { "getContentResolver", "()Landroid/content/ContentResolver;",
          (void *)enko_ctxwrapper_getContentResolver },
    };
    size_t n_targets = sizeof(targets) / sizeof(targets[0]);

    JNINativeMethod register_list[16];
    int register_count = 0;

    for (size_t i = 0; i < n_targets; i++) {
        jmethodID m = (*env)->GetMethodID(env, cw, targets[i].name, targets[i].sig);
        if (!m) {
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            LOGW("could not resolve ContextWrapper.%s — skipping", targets[i].name);
            continue;
        }
        if (set_method_native(m) != 0) {
            LOGW("set_method_native(%s) failed — skipping", targets[i].name);
            continue;
        }
        if (redirect_to_jni_trampoline(m, trampoline, &layout) != 0) {
            LOGW("redirect_to_jni_trampoline(%s) failed — skipping", targets[i].name);
            continue;
        }
        register_list[register_count].name = targets[i].name;
        register_list[register_count].signature = targets[i].sig;
        register_list[register_count].fnPtr = targets[i].impl;
        register_count++;
    }

    /* The `mid` from the original GetMethodID was for attachBaseContext —
     * still need that bound. The loop above covers it. Suppress unused. */
    (void)mid;

    jint rc = (*env)->RegisterNatives(env, cw, register_list, register_count);
    (*env)->DeleteLocalRef(env, cw);

    if (rc != JNI_OK) {
        LOGE("RegisterNatives failed (rc=%d)", rc);
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        return -1;
    }

    LOGI("ContextWrapper hooks installed (%d methods)", register_count);
    return 0;
}
