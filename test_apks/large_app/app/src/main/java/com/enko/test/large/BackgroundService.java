package com.enko.test.large;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;

public class BackgroundService extends Service {
    @Override
    public IBinder onBind(Intent intent) { return null; }
}
