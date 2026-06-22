package com.example.demo;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

/**
 * Receives system broadcasts (boot, package events, connectivity).
 */
public class BootReceiver extends BroadcastReceiver {
    private static final String TAG = "BootReceiver";

    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent != null ? intent.getAction() : "null";
        Log.i(TAG, "Received broadcast: " + action);

        if (Intent.ACTION_BOOT_COMPLETED.equals(action)) {
            Log.i(TAG, "Device booted — checking license state");
            LicenseManager lm = new LicenseManager(context);
            if (lm.isActivated()) {
                Intent svc = new Intent(context, DemoService.class);
                context.startService(svc);
            }
        }
    }
}
