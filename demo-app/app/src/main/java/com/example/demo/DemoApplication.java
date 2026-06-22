package com.example.demo;

import android.app.Application;
import android.util.Log;

public class DemoApplication extends Application {
    private static final String TAG = "DemoApp";
    private static DemoApplication instance;

    @Override
    public void onCreate() {
        super.onCreate();
        instance = this;
        Log.i(TAG, "DemoApplication.onCreate()");
        Log.i(TAG, "Backend: " + SecretConfig.BACKEND_URL);
        Log.i(TAG, "WS: " + SecretConfig.WEBSOCKET_URL);

        // Warm up crypto engine
        CryptoHelper crypto = new CryptoHelper();
        String test = crypto.encrypt("init_check");
        Log.d(TAG, "Crypto engine ready: " + (test != null));
    }

    static DemoApplication getInstance() {
        return instance;
    }
}
