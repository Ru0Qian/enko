package com.enko.shell;

import android.app.Application;
import android.content.Context;
import android.content.ContextWrapper;
import android.util.Log;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;

/**
 * Reflection-based Application reference replacement.
 *
 * <p>Replaces ActivityThread / LoadedApk references that point at the shell
 * Application (ProxyApplication) with the user's real Application. This is
 * required so that code like {@code ((MyApp) ctx.getApplicationContext())}
 * — common in Hilt, custom DI, and many libraries — finds the right class.
 *
 * <p>The historical {@code replaceAppClassLoader} method was removed when
 * the shell switched from "replace LoadedApk.mClassLoader with a custom
 * InMemoryDex one" to "append payload DEX elements directly into the
 * framework PathClassLoader's pathList" — see {@link DexInjector}. With
 * the new approach we leave every classloader-related framework field
 * untouched, which fixes Android-9-era SIGSEGVs in AppCompatActivity's
 * attach path and gets out of the way of Hilt / AndroidX assumptions.
 */
public final class ApplicationReplacer {

    private static final String TAG = "EnkoShell";

    private ApplicationReplacer() {}

    // ── Real Application binding ──────────────────────────────────────────

    /**
     * Phase 1 (called from attachBaseContext): create real Application and
     * call its attachBaseContext so ContentProviders can access it.
     * Field replacements are NOT done here because
     * LoadedApk.makeApplication() will overwrite
     * mApplication/mInitialApplication/mAllApplications after
     * attachBaseContext returns.
     *
     * @return the newly created real Application instance
     */
    public static Application bindRealApplication(
            ClassLoader payloadLoader,
            String className,
            Context baseContext) throws Exception {
        Class<?> clz = Class.forName(className, true, payloadLoader);
        Object instance = clz.getDeclaredConstructor().newInstance();
        if (!(instance instanceof Application)) {
            throw new IllegalStateException(
                    className + " is not an Application");
        }

        Application app = (Application) instance;
        /* Belt-and-suspenders: invoke attachBaseContext via reflection AND
         * also write the mBase field directly. Reflection's Method.invoke
         * with a method handle resolved from ContextWrapper.class dispatches
         * virtually — if the realApp's class overrides attachBaseContext
         * but forgets to call super.attachBaseContext(base), our mBase
         * stays null and EVERY downstream ContextWrapper.getApplicationInfo
         * call segfaults in ART's AOT'd boot.oat (ContextWrapper.mBase
         * dereference at +53). Writing the field unconditionally afterwards
         * is harmless when attachBaseContext did the right thing, and
         * fixes the crash when it didn't. */
        Method attachBaseContextMethod = ContextWrapper.class
                .getDeclaredMethod("attachBaseContext", Context.class);
        attachBaseContextMethod.setAccessible(true);
        try {
            attachBaseContextMethod.invoke(app, baseContext);
        } catch (Throwable t) {
            Log.w(TAG, "attachBaseContext invocation threw — will set mBase directly", t);
        }
        try {
            Field mBaseField = ContextWrapper.class.getDeclaredField("mBase");
            mBaseField.setAccessible(true);
            if (mBaseField.get(app) == null) {
                mBaseField.set(app, baseContext);
                Log.w(TAG, "mBase was null after attachBaseContext; set directly");
            }
        } catch (Throwable t) {
            Log.e(TAG, "failed to backfill mBase on real Application", t);
        }
        return app;
    }

    // ── Application reference replacement ─────────────────────────────────

    /**
     * Phase 2 (called from onCreate): replace all framework references to
     * the shell Application with the real Application.  By this point
     * makeApplication() has completed, so our replacements won't be
     * overwritten.
     */
    @SuppressWarnings("unchecked")
    public static void replaceApplicationReferences(
            Application shellApp, Application realApp) {
        try {
            Class<?> activityThreadClass =
                    Class.forName("android.app.ActivityThread");
            Method currentThreadMethod = activityThreadClass
                    .getDeclaredMethod("currentActivityThread");
            currentThreadMethod.setAccessible(true);
            Object activityThread = currentThreadMethod.invoke(null);

            Field mInitialApplicationField = activityThreadClass
                    .getDeclaredField("mInitialApplication");
            mInitialApplicationField.setAccessible(true);
            mInitialApplicationField.set(activityThread, realApp);

            Field mAllApplicationsField = activityThreadClass
                    .getDeclaredField("mAllApplications");
            mAllApplicationsField.setAccessible(true);
            ArrayList<Application> mAllApplications =
                    (ArrayList<Application>)
                            mAllApplicationsField.get(activityThread);
            mAllApplications.remove(shellApp);
            if (!mAllApplications.contains(realApp)) {
                mAllApplications.add(realApp);
            }

            Field mBoundApplicationField = activityThreadClass
                    .getDeclaredField("mBoundApplication");
            mBoundApplicationField.setAccessible(true);
            Object appBindData =
                    mBoundApplicationField.get(activityThread);
            if (appBindData != null) {
                Field infoField = appBindData.getClass()
                        .getDeclaredField("info");
                infoField.setAccessible(true);
                Object loadedApk = infoField.get(appBindData);
                if (loadedApk != null) {
                    Field mApplicationField = loadedApk.getClass()
                            .getDeclaredField("mApplication");
                    mApplicationField.setAccessible(true);
                    mApplicationField.set(loadedApk, realApp);
                }
            }
            Log.i(TAG, "application references replaced successfully");
        } catch (Throwable t) {
            Log.e(TAG, "failed to replace application references", t);
        }
    }
}
