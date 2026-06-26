package com.enko.shell;

import android.app.Activity;
import android.app.AppComponentFactory;
import android.app.Application;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.ContentProvider;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.util.Log;

import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.zip.ZipFile;

/**
 * AppComponentFactory-based shell entry point. Available API 28+. Replaces
 * the ProxyApplication wrap-and-replace pattern with a cleaner approach
 * that doesn't change the manifest's application:name from the user's
 * real class.
 *
 * <p>Flow on Android 9+:
 * <ol>
 *   <li>Manifest sets {@code application:name="com.user.RealApplication"}
 *       and {@code appComponentFactory="com.enko.shell.EnkoComponentFactory"}.
 *   <li>Framework loads this factory before any component instance.
 *   <li>First {@link #instantiateApplication} call triggers payload
 *       decryption + dex injection into the framework PathClassLoader.
 *   <li>We return a fresh instance of the user's real Application,
 *       loaded via the now-extended classloader; the framework calls
 *       {@code app.attach(appContext)} itself — no wrapper involved.
 * </ol>
 *
 * <p>Pre-API-28 devices ignore {@code appComponentFactory} and fall back
 * to the legacy ProxyApplication path (still wired in via manifest as
 * the secondary entry point).
 */
@android.annotation.TargetApi(28)
public final class EnkoComponentFactory extends AppComponentFactory {
    private static final String TAG = "EnkoShell";

    private static volatile boolean installed = false;
    private static volatile String realAppClass = null;
    private static final Object INSTALL_LOCK = new Object();

    @Override
    public Application instantiateApplication(ClassLoader cl, String className)
            throws InstantiationException, IllegalAccessException,
                   ClassNotFoundException {
        ensureInstalled(cl);
        // Framework will pass className from manifest application:name. We
        // honor it, but prefer the realApplicationClass discovered during
        // install (which is what the user actually had before hardening).
        String target = (realAppClass != null && !realAppClass.isEmpty())
                ? realAppClass : className;
        try {
            return super.instantiateApplication(cl, target);
        } catch (ClassNotFoundException e) {
            Log.w(TAG, "could not load real app class '" + target
                    + "', falling back to manifest className '" + className
                    + "'");
            return super.instantiateApplication(cl, className);
        }
    }

    @Override
    public Activity instantiateActivity(ClassLoader cl, String className,
                                        Intent intent)
            throws InstantiationException, IllegalAccessException,
                   ClassNotFoundException {
        ensureInstalled(cl);
        return super.instantiateActivity(cl, className, intent);
    }

    @Override
    public Service instantiateService(ClassLoader cl, String className,
                                      Intent intent)
            throws InstantiationException, IllegalAccessException,
                   ClassNotFoundException {
        ensureInstalled(cl);
        return super.instantiateService(cl, className, intent);
    }

    @Override
    public ContentProvider instantiateProvider(ClassLoader cl, String className)
            throws InstantiationException, IllegalAccessException,
                   ClassNotFoundException {
        ensureInstalled(cl);
        return super.instantiateProvider(cl, className);
    }

    @Override
    public BroadcastReceiver instantiateReceiver(ClassLoader cl, String className,
                                                 Intent intent)
            throws InstantiationException, IllegalAccessException,
                   ClassNotFoundException {
        ensureInstalled(cl);
        return super.instantiateReceiver(cl, className, intent);
    }

    private static void ensureInstalled(ClassLoader cl) {
        if (installed) return;
        synchronized (INSTALL_LOCK) {
            if (installed) return;
            try {
                Context base = systemContextFromActivityThread();
                if (base == null) {
                    throw new IllegalStateException(
                            "cannot obtain bound context for install");
                }
                ProxyApplication.InstallResult r =
                        ProxyApplication.installPayloadCore(base, cl, null, true);
                realAppClass = (r != null && r.cfg != null)
                        ? r.cfg.realApplicationClass : null;
                installed = true;
                Log.i(TAG, "EnkoComponentFactory install complete, realAppClass='"
                        + realAppClass + "'");
            } catch (Throwable t) {
                Log.e(TAG, "EnkoComponentFactory install failed", t);
                throw new RuntimeException(
                        "Enko payload install failed", t);
            }
        }
    }

    /**
     * Recover a proper app-scoped Context at the AppComponentFactory.
     * instantiateApplication boundary. The user-facing Application
     * hasn't been constructed yet, so we walk ActivityThread reflectively
     * to find the LoadedApk and ask ContextImpl.createAppContext to
     * build the same per-app context the framework would normally pass
     * to Application.attach a few moments later.
     *
     * <p>This is strictly app-scoped (per-package data dir, classloader,
     * PackageManager) so the native rollback guard's getFilesDir() and
     * versionCode lookups return the values we expect.
     */
    private static Context systemContextFromActivityThread() {
        try {
            Class<?> atC = Class.forName("android.app.ActivityThread");
            Method current = atC.getDeclaredMethod("currentActivityThread");
            Object at = current.invoke(null);
            if (at == null) return null;

            Field boundF = atC.getDeclaredField("mBoundApplication");
            boundF.setAccessible(true);
            Object bound = boundF.get(at);
            if (bound != null) {
                Field infoF = bound.getClass().getDeclaredField("info");
                infoF.setAccessible(true);
                Object loadedApk = infoF.get(bound);
                if (loadedApk != null) {
                    Class<?> ctxImplC = Class.forName("android.app.ContextImpl");
                    Method createAppCtx = ctxImplC.getDeclaredMethod(
                            "createAppContext", atC, loadedApk.getClass());
                    createAppCtx.setAccessible(true);
                    Object appContext = createAppCtx.invoke(null, at, loadedApk);
                    if (appContext instanceof Context) {
                        return (Context) appContext;
                    }
                }
            }
            // Fallback: bare system context — getFilesDir() and the
            // rollback guard will likely fail, but at least PackageManager
            // is available so the caller can continue diagnostics.
            Method getSys = atC.getMethod("getSystemContext");
            return (Context) getSys.invoke(at);
        } catch (Throwable t) {
            Log.w(TAG, "systemContextFromActivityThread failed: " + t);
            return null;
        }
    }
}
