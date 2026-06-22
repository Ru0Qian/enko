package com.enko.test.small;

import android.app.Application;
import android.util.Log;

public class SmallTestApp extends Application {
    private static final String TAG = "SmallTestApp";

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "Application onCreate");
    }

    @Override
    protected void attachBaseContext(android.content.Context base) {
        super.attachBaseContext(base);
        Log.i(TAG, "attachBaseContext");
    }
}
