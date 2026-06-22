package com.example.demo;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.util.Log;

/**
 * Background service that performs periodic security checks.
 */
public class DemoService extends Service {
    private static final String TAG = "DemoService";
    private final IBinder binder = new LocalBinder();
    private volatile boolean running;
    private Thread workerThread;

    public class LocalBinder extends Binder {
        DemoService getService() { return DemoService.this; }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "Service created");
        running = true;
        workerThread = new Thread(this::backgroundWork, "demo-worker");
        workerThread.setDaemon(true);
        workerThread.start();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return binder;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.i(TAG, "Service started, id=" + startId);
        return START_STICKY;
    }

    private void backgroundWork() {
        int tick = 0;
        while (running) {
            try {
                Thread.sleep(5000);
                tick++;
                Log.d(TAG, "heartbeat #" + tick
                        + " crypto=" + verifyCryptoIntegrity()
                        + " env=" + checkEnvironment());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private boolean verifyCryptoIntegrity() {
        try {
            CryptoHelper crypto = new CryptoHelper();
            String enc = crypto.encrypt("integrity_check");
            String dec = crypto.decrypt(enc);
            return "integrity_check".equals(dec);
        } catch (Exception e) {
            return false;
        }
    }

    private String checkEnvironment() {
        StringBuilder sb = new StringBuilder();
        sb.append("pkg=").append(getPackageName());
        sb.append(",pid=").append(android.os.Process.myPid());
        sb.append(",uid=").append(android.os.Process.myUid());
        return sb.toString();
    }

    @Override
    public void onDestroy() {
        running = false;
        if (workerThread != null) workerThread.interrupt();
        Log.i(TAG, "Service destroyed");
        super.onDestroy();
    }
}
