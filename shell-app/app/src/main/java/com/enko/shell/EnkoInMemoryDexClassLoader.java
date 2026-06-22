package com.enko.shell;

import android.util.Log;
import dalvik.system.BaseDexClassLoader;
import dalvik.system.InMemoryDexClassLoader;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;

/**
 * Custom ClassLoader that intercepts class loading to restore extracted
 * method bodies on-demand (per-class) before the verifier sees the class.
 *
 * <p>{@code InMemoryDexClassLoader} is {@code final} so we extend
 * {@link BaseDexClassLoader} directly and steal the internal {@code pathList}
 * from a temporary IMDCL via reflection. This is the same technique used by
 * Android hot-fix frameworks (Tinker, Robust, etc.).
 *
 * <p>Flow:
 * <ol>
 *   <li>NativeBridge.nativeExtractLoad(blob) — decrypt + parse extraction entries.</li>
 *   <li>NativeBridge.nativeExtractBindDexBuffers(addrs, sizes, count) — build class→entry index.</li>
 *   <li>For each class loaded: findClass() → nativeExtractRestoreClass() → super.findClass().</li>
 * </ol>
 *
 * <p>Fail-close: if restoreClass returns &lt; 0, findClass throws ClassNotFoundException.
 */
@SuppressWarnings("deprecation")
final class EnkoInMemoryDexClassLoader extends BaseDexClassLoader {
    private static final String TAG = "EnkoShell";

    private volatile boolean extractActive;

    EnkoInMemoryDexClassLoader(ByteBuffer[] dexBuffers, ClassLoader parent,
                               boolean extractActive) {
        super("", null, null, parent);
        this.extractActive = extractActive;

        /* Steal the pathList from a temporary InMemoryDexClassLoader so that
         * our BaseDexClassLoader can resolve classes from the ByteBuffer[]. */
        InMemoryDexClassLoader tmp = new InMemoryDexClassLoader(dexBuffers, parent);
        try {
            Field plField = BaseDexClassLoader.class.getDeclaredField("pathList");
            plField.setAccessible(true);
            Object pathList = plField.get(tmp);

            /* Update the definingContext inside DexPathList to point to *us*
             * so that classes resolved through pathList are associated with
             * this ClassLoader instance (not the temporary one). */
            Field dcField = pathList.getClass().getDeclaredField("definingContext");
            dcField.setAccessible(true);
            dcField.set(pathList, this);

            plField.set(this, pathList);
        } catch (Exception e) {
            throw new RuntimeException("Failed to init EnkoInMemoryDexClassLoader", e);
        }
    }

    /**
     * Delegate native library lookup to the parent classloader (the original
     * PathClassLoader) which has the correct nativeLibraryDirectories.
     * Our stolen pathList from InMemoryDexClassLoader only contains system
     * lib dirs, so third-party native libs (e.g., libcronet) won't be found
     * without this delegation.
     */
    @Override
    public String findLibrary(String name) {
        String path = super.findLibrary(name);
        if (path != null) return path;
        ClassLoader parent = getParent();
        if (parent instanceof BaseDexClassLoader) {
            return ((BaseDexClassLoader) parent).findLibrary(name);
        }
        return null;
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        if (extractActive) {
            /* Convert Java class name (com.example.Foo) to DEX type descriptor
             * (Lcom/example/Foo;). */
            String desc = "L" + name.replace('.', '/') + ";";
            int rc = NativeBridge.nativeExtractRestoreClass(desc);
            if (rc < 0) {
                /* Fail-close: extraction system reported an error. */
                throw new ClassNotFoundException(
                        "extract restore failed for " + name + " (rc=" + rc + ")");
            }
            /* rc == 0 means class had no extracted methods — normal. */
        }
        return super.findClass(name);
    }

    /**
     * Called when the native extraction runtime signals that all methods
     * have been restored (pending_count == 0). After this, findClass
     * skips the native call entirely.
     */
    void disableExtract() {
        extractActive = false;
    }
}
