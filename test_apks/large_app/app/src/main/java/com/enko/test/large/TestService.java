package com.enko.test.large;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;

public class TestService extends Service {
    private static final String TAG = "TestService";

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "onCreate");
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.i(TAG, "onStartCommand");
        new Thread(() -> {
            for (int i = 0; i < 10; i++) {
                Log.d(TAG, "Working... " + i);
                DataStore.put("svc_" + i, "val_" + i);
                try { Thread.sleep(100); } catch (Exception e) {}
            }
            stopSelf();
        }).start();
        return START_NOT_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) { return null; }
}
