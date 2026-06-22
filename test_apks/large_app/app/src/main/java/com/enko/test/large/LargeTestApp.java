package com.enko.test.large;

import android.app.Application;
import android.util.Log;

public class LargeTestApp extends Application {
    private static final String TAG = "LargeTestApp";
    public static String APP_VERSION = "1.0.0";

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "Application onCreate");
        preloadData();
    }

    @Override
    protected void attachBaseContext(android.content.Context base) {
        super.attachBaseContext(base);
        Log.i(TAG, "attachBaseContext");
    }

    private void preloadData() {
        for (int i = 0; i < 100; i++) {
            DataStore.put("key_" + i, "value_" + i);
        }
        Log.i(TAG, "Data preloaded: " + DataStore.size());
    }
}
