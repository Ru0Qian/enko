package com.enko.shell;

import android.util.Log;
import dalvik.system.BaseDexClassLoader;
import dalvik.system.InMemoryDexClassLoader;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;

/**
 * Append payload DEX buffers into the framework-created PathClassLoader
 * WITHOUT replacing the ClassLoader instance.
 *
 * <p>This is the "dex injection" technique that hot-patch frameworks like
 * Tinker / Robust / Tencent Lego / Aliyun Sophix use. Unlike the older
 * "ClassLoader replacement" approach (where you create a custom
 * BaseDexClassLoader subclass and overwrite LoadedApk.mClassLoader), this
 * leaves every field the Android framework caches about the classloader
 * untouched: native library search namespace, mDefaultClassLoader,
 * ContextImpl.mClassLoader, mResources's classloader binding, AppCompat /
 * Hilt / AndroidX assumptions, etc. The only thing that changes is the
 * contents of the dexElements array deep inside the existing
 * PathClassLoader's DexPathList — the array grows, and lookups now find
 * the payload classes too.
 *
 * <p>Compared with replacing the ClassLoader, this:
 * <ul>
 *   <li>Avoids Android 9's SIGSEGV in {@code ContextWrapper.getApplicationInfo+53}
 *       triggered when AppCompatActivity.attachBaseContext runs against a
 *       wrapper-replaced ClassLoader whose stolen pathList's defaultClassLoader
 *       disagrees with mResources's defining context.
 *   <li>Removes the need to reflectively patch LoadedApk.mClassLoader,
 *       LoadedApk.mDefaultClassLoader, and ContextImpl.mClassLoader on every
 *       Android version (each version has slightly different field names /
 *       presence).
 *   <li>Keeps native library lookups working by default — no manual
 *       splicing of nativeLibraryDirectories.
 * </ul>
 *
 * <p>The technique relies on three internal field names that have been
 * stable since API 14 (Android 4.0):
 * <pre>
 *   BaseDexClassLoader.pathList   :  DexPathList
 *   DexPathList.dexElements       :  Element[]   (DexPathList.Element)
 *   InMemoryDexClassLoader's internal pathList.dexElements  :
 *       Element[] populated from ByteBuffer[] passed to its constructor
 * </pre>
 *
 * <p>Procedure:
 * <ol>
 *   <li>Create a throw-away {@link InMemoryDexClassLoader} from the
 *       payload {@code ByteBuffer[]}. This is the only public API that
 *       lets us turn ByteBuffer[] into well-formed DexPathList.Element[]
 *       instances. We never expose this temp ClassLoader to anyone.
 *   <li>Reflect out the throw-away CL's {@code pathList.dexElements}.
 *   <li>Build a fresh {@code Element[]} = payload elements ++ base
 *       elements. Putting payload first means payload classes win on
 *       name collision, which matches the "replace shell stub with real
 *       app class" intent of method-extract / VMP.
 *   <li>Reflect-write the new array into the framework's PathClassLoader.
 * </ol>
 */
final class DexInjector {
    private static final String TAG = "EnkoShell";

    private DexInjector() {}

    /**
     * Inject the given dex buffers into the framework-created
     * {@link BaseDexClassLoader} that the system uses for this process.
     *
     * @param baseClassLoader the PathClassLoader Android handed us
     *                        (usually {@code Application.getClassLoader()})
     * @param dexBuffers      direct ByteBuffers containing the decrypted
     *                        payload DEX files, with valid headers
     *                        (caller must have run refreshDexHeader on each)
     */
    static void injectDexes(ClassLoader baseClassLoader, ByteBuffer[] dexBuffers)
            throws Exception {
        if (!(baseClassLoader instanceof BaseDexClassLoader)) {
            throw new IllegalStateException(
                    "expected BaseDexClassLoader, got "
                            + baseClassLoader.getClass().getName());
        }

        /* Step 1: turn ByteBuffer[] into Element[] via a temp IMDCL.
         * Parent=null is intentional — we never use this CL for resolution. */
        InMemoryDexClassLoader temp = new InMemoryDexClassLoader(
                dexBuffers, ClassLoader.getSystemClassLoader().getParent());

        Field pathListField = BaseDexClassLoader.class
                .getDeclaredField("pathList");
        pathListField.setAccessible(true);

        Object tempPathList = pathListField.get(temp);
        Object basePathList = pathListField.get(baseClassLoader);

        Field elementsField = tempPathList.getClass()
                .getDeclaredField("dexElements");
        elementsField.setAccessible(true);

        Object payloadElements = elementsField.get(tempPathList);
        Object baseElements = elementsField.get(basePathList);

        int payloadLen = Array.getLength(payloadElements);
        int baseLen = Array.getLength(baseElements);

        /* Step 2: combine — payload first so its classes shadow the shell
         * stubs (matters when our VMP/extract has left the shell DEX with
         * native-stub method bodies for app classes we just decrypted). */
        Object merged = Array.newInstance(
                payloadElements.getClass().getComponentType(),
                payloadLen + baseLen);
        System.arraycopy(payloadElements, 0, merged, 0, payloadLen);
        System.arraycopy(baseElements, 0, merged, payloadLen, baseLen);

        /* Step 3: write back. PathClassLoader on the next loadClass() will
         * walk this expanded array and find our payload classes. The
         * ClassLoader instance, its parent chain, its nativeLibraryDirs,
         * the LoadedApk reference to it — all unchanged. */
        elementsField.set(basePathList, merged);

        /* Also redirect the temp IMDCL's classes (via its definingContext)
         * to point at the base CL so any classes accidentally already
         * resolved through it report the right defining loader. Best
         * effort — older API levels may not have this field. */
        try {
            Field dcField = tempPathList.getClass()
                    .getDeclaredField("definingContext");
            dcField.setAccessible(true);
            dcField.set(tempPathList, baseClassLoader);
        } catch (NoSuchFieldException ignore) {
            /* not present on this API level — harmless */
        }

        Log.i(TAG, "injected " + payloadLen
                + " payload DEX element(s) into "
                + baseClassLoader.getClass().getSimpleName()
                + " (existing=" + baseLen + ", new total="
                + (payloadLen + baseLen) + ")");
    }
}
