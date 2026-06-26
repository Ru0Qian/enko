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
