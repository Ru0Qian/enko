package com.enko.shell;

import android.app.Application;
import android.content.Context;
import android.content.ContextWrapper;
import android.util.Log;
import java.lang.ref.WeakReference;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Map;

/**
 * Reflection-based Application and ClassLoader replacement.
 *
 * Hooks into the Android framework internals to swap the shell Application
 * with the real (payload) Application after payload DEX loading.
 */
public final class ApplicationReplacer {

    private static final String TAG = "EnkoShell";

    private ApplicationReplacer() {}

    // ── ClassLoader replacement ───────────────────────────────────────────

    @SuppressWarnings("unchecked")
    public static void replaceAppClassLoader(
            Context context, ClassLoader newLoader) throws Exception {
        Class<?> activityThreadClass =
                Class.forName("android.app.ActivityThread");
        Method currentThreadMethod = activityThreadClass
                .getDeclaredMethod("currentActivityThread");
        currentThreadMethod.setAccessible(true);
        Object activityThread = currentThreadMethod.invoke(null);

        Field mPackagesField = activityThreadClass
                .getDeclaredField("mPackages");
        mPackagesField.setAccessible(true);
        Map<String, WeakReference<?>> mPackages =
                (Map<String, WeakReference<?>>)
                        mPackagesField.get(activityThread);
        WeakReference<?> loadedApkRef =
                mPackages.get(context.getPackageName());
        if (loadedApkRef == null || loadedApkRef.get() == null) {
            throw new IllegalStateException("cannot resolve LoadedApk");
        }

        Object loadedApk = loadedApkRef.get();
        Field mClassLoaderField = loadedApk.getClass()
                .getDeclaredField("mClassLoader");
        mClassLoaderField.setAccessible(true);
        mClassLoaderField.set(loadedApk, newLoader);
    }

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
        Method attachBaseContextMethod = ContextWrapper.class
                .getDeclaredMethod("attachBaseContext", Context.class);
        attachBaseContextMethod.setAccessible(true);
        attachBaseContextMethod.invoke(app, baseContext);
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
