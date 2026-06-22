package com.enko.test.scenario;

import android.app.Application;
import android.content.SharedPreferences;

public class ScenarioApplication extends Application {
    static final String PREFS = "scenario-state";

    @Override
    public void onCreate() {
        super.onCreate();
        SharedPreferences prefs = getSharedPreferences(PREFS, MODE_PRIVATE);
        int launches = prefs.getInt("launches", 0) + 1;
        prefs.edit().putInt("launches", launches).apply();
    }
}
