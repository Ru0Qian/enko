package com.enko.test.large;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

public class SecondActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_second);
        findViewById(R.id.btn_back).setOnClickListener(v -> finish());
        TextView info = findViewById(R.id.info);
        info.setText("Page 2 | Data: " + DataStore.size()
            + " keys | DB: " + DatabaseHelper.getStatus());
    }
}
