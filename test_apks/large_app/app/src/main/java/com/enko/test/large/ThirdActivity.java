package com.enko.test.large;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

public class ThirdActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_third);
        findViewById(R.id.btn_math).setOnClickListener(v -> {
            String result = Calculator.compute("fib", 20);
            TextView tv = findViewById(R.id.result);
            tv.setText("Result: " + result);
        });
    }
}
