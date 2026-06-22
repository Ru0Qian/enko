package com.enko.test.large;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;
import android.content.Intent;
import android.util.Log;

public class MainActivity extends Activity {
    private static final String TAG = "LargeMain";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Log.i(TAG, "onCreate");

        TextView status = findViewById(R.id.status);
        status.setText("App: " + LargeTestApp.APP_VERSION
            + " | Data: " + DataStore.size() + " keys");

        findViewById(R.id.btn_second).setOnClickListener(v ->
            startActivity(new Intent(this, SecondActivity.class)));
        findViewById(R.id.btn_third).setOnClickListener(v ->
            startActivity(new Intent(this, ThirdActivity.class)));
        findViewById(R.id.btn_service).setOnClickListener(v -> {
            startService(new Intent(this, TestService.class));
            status.setText("Service started!");
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        TextView status = findViewById(R.id.status);
        if (status != null)
            status.setText("Resumed | Data: " + DataStore.size() + " keys");
    }
}
