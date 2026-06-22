#include <jni.h>
#include <stdint.h>
#include <string.h>

static const uint8_t kFlagXor[] = {
    0x45, 0x4F, 0x42, 0x44, 0x58, 0x46, 0x4D, 0x48,
    0x4C, 0x7C, 0x4E, 0x42, 0x57, 0x51, 0x4A, 0x5B,
    0x7C, 0x11, 0x13, 0x11, 0x15, 0x5E,
};

JNIEXPORT jboolean JNICALL
Java_com_enko_test_scenario_NativeScenarioVerifier_nativeVerify(
        JNIEnv *env,
        jclass clazz,
        jstring input) {
    (void)clazz;
    if (input == NULL) {
        return JNI_FALSE;
    }

    const char *chars = (*env)->GetStringUTFChars(env, input, NULL);
    if (chars == NULL) {
        return JNI_FALSE;
    }

    char expected[sizeof(kFlagXor) + 1];
    for (size_t i = 0; i < sizeof(kFlagXor); i++) {
        expected[i] = (char)(kFlagXor[i] ^ 0x23U);
    }
    expected[sizeof(kFlagXor)] = '\0';

    int ok = strcmp(chars, expected) == 0;
    memset(expected, 0, sizeof(expected));
    (*env)->ReleaseStringUTFChars(env, input, chars);
    return ok ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL
Java_com_enko_test_scenario_NativeScenarioVerifier_nativeBusinessScore(
        JNIEnv *env,
        jclass clazz,
        jstring input,
        jint total_cents,
        jstring session_token) {
    (void) clazz;
    if (input == NULL || session_token == NULL) {
        return -1;
    }

    const char *chars = (*env)->GetStringUTFChars(env, input, NULL);
    const char *token = (*env)->GetStringUTFChars(env, session_token, NULL);
    if (chars == NULL || token == NULL) {
        if (chars != NULL) {
            (*env)->ReleaseStringUTFChars(env, input, chars);
        }
        if (token != NULL) {
            (*env)->ReleaseStringUTFChars(env, session_token, token);
        }
        return -1;
    }

    uint32_t acc = 0x811C9DC5u ^ (uint32_t) total_cents;
    for (const unsigned char *p = (const unsigned char *) chars; *p; ++p) {
        acc ^= (uint32_t) *p;
        acc *= 16777619u;
    }
    for (const unsigned char *p = (const unsigned char *) token; *p; ++p) {
        acc ^= (uint32_t) *p;
        acc *= 16777619u;
    }

    (*env)->ReleaseStringUTFChars(env, input, chars);
    (*env)->ReleaseStringUTFChars(env, session_token, token);
    return (jint) (acc & 0x7FFFFFFFu);
}
