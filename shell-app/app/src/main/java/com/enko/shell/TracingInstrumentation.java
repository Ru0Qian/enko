package com.enko.shell;

import android.app.Activity;
import android.app.Application;
import android.app.Instrumentation;
import android.content.ComponentName;
import android.content.ContextWrapper;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

import java.lang.reflect.Field;

/**
 * Wraps the system Instrumentation to log every step of Activity construction
 * so we can pinpoint which call in the launch sequence dereferences a null
 * ContextWrapper.mBase. Forwards everything to the original instance.
 */
final class TracingInstrumentation extends Instrumentation {
    private static final String TAG = "EnkoShell";
    private final Instrumentation orig;

    TracingInstrumentation(Instrumentation orig) {
        this.orig = orig;
    }

    private static String dumpCtx(ContextWrapper cw) {
        if (cw == null) return "<null wrapper>";
        try {
            Field mBaseF = ContextWrapper.class.getDeclaredField("mBase");
            mBaseF.setAccessible(true);
            Object mBase = mBaseF.get(cw);
            return cw.getClass().getSimpleName() + "(mBase="
                    + (mBase == null ? "<NULL>" : mBase.getClass().getSimpleName())
                    + ")";
        } catch (Throwable t) {
            return cw.getClass().getSimpleName() + "(?)";
        }
    }

    @Override
    public Activity newActivity(ClassLoader cl, String className, Intent intent)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        Log.i(TAG, "[trace] newActivity className=" + className);
        Activity a = orig.newActivity(cl, className, intent);
        /* CRITICAL: ART's framework path on Android 9 (and AppCompatActivity
         * in AndroidX) walks paths between newActivity and activity.attach
         * that dereference activity.mBase via ContextWrapper.getApplicationInfo.
         * Because activity.attach() is what eventually sets mBase, those
         * paths SIGSEGV. We can't change framework code, so pre-seed the
         * Activity's mBase with the running Application's mBase (a real
         * ContextImpl). When activity.attach() later runs, ContextWrapper.
         * attachBaseContext overwrites mBase with the proper Activity
         * ContextImpl — our pre-seeded value is replaced cleanly. */
        try {
            android.app.Application app = (android.app.Application) Class
                    .forName("android.app.ActivityThread")
                    .getMethod("currentApplication").invoke(null);
            if (app != null) {
                Field appBaseF = ContextWrapper.class.getDeclaredField("mBase");
                appBaseF.setAccessible(true);
                Object appBase = appBaseF.get(app);
                if (appBase != null) {
                    appBaseF.set(a, appBase);
                    Log.i(TAG, "[trace] pre-seeded mBase on " + className);
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "[trace] pre-seed mBase failed", t);
        }
        Log.i(TAG, "[trace] newActivity returned " + dumpCtx(a));
        return a;
    }

    @Override
    public Application newApplication(ClassLoader cl, String className,
            android.content.Context context) throws InstantiationException,
            IllegalAccessException, ClassNotFoundException {
        Log.i(TAG, "[trace] newApplication className=" + className);
        return orig.newApplication(cl, className, context);
    }

    @Override
    public void callActivityOnCreate(Activity activity, Bundle bundle) {
        Log.i(TAG, "[trace] PRE-OnCreate " + dumpCtx(activity));
        try {
            orig.callActivityOnCreate(activity, bundle);
        } catch (Throwable t) {
            Log.e(TAG, "[trace] callActivityOnCreate THREW", t);
            throw t;
        }
        Log.i(TAG, "[trace] POST-OnCreate " + activity.getClass().getSimpleName());
    }

    @Override
    public void callActivityOnCreate(Activity activity, Bundle bundle,
                                     android.os.PersistableBundle pbundle) {
        Log.i(TAG, "[trace] PRE-OnCreate(p) " + dumpCtx(activity));
        try {
            orig.callActivityOnCreate(activity, bundle, pbundle);
        } catch (Throwable t) {
            Log.e(TAG, "[trace] callActivityOnCreate(p) THREW", t);
            throw t;
        }
        Log.i(TAG, "[trace] POST-OnCreate(p) " + activity.getClass().getSimpleName());
    }

    @Override
    public void callActivityOnStart(Activity activity) {
        Log.i(TAG, "[trace] PRE-OnStart " + dumpCtx(activity));
        orig.callActivityOnStart(activity);
    }

    @Override
    public void callApplicationOnCreate(Application app) {
        Log.i(TAG, "[trace] callApplicationOnCreate " + app.getClass().getSimpleName());
        orig.callApplicationOnCreate(app);
    }
}
