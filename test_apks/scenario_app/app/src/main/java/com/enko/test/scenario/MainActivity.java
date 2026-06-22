package com.enko.test.scenario;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

public class MainActivity extends Activity {
    private static final String TAG = "ScenarioMain";
    private static final String COMPLEX_BUSINESS = "complex-business";
    private int stateTouches = 0;

    private TextView status;
    private EditText flagInput;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        status = findViewById(R.id.status);
        flagInput = findViewById(R.id.flagInput);
        TextView scenario = findViewById(R.id.scenario);
        scenario.setText("Scenario: " + BuildConfig.SCENARIO_KIND);

        Button verify = findViewById(R.id.btnVerify);
        verify.setOnClickListener(v -> {
            String input = flagInput.getText().toString().trim();
            boolean ok = verifySubmittedFlag(input);
            Log.i(TAG, "verify result=" + ok + " scenario=" + BuildConfig.SCENARIO_KIND);
            if (ok) {
                status.setText("*** CORRECT! Flag accepted. ***");
            } else {
                status.setText("Incorrect flag, try again.");
            }
        });

        Button state = findViewById(R.id.btnState);
        if (COMPLEX_BUSINESS.equals(BuildConfig.SCENARIO_KIND)) {
            state.setText("Trigger Business");
            state.setOnClickListener(v -> runBusinessTrigger(state));
        } else {
            state.setOnClickListener(v -> {
                stateTouches++;
                status.setText("State touched: " + stateTouches);
            });
        }

        Log.i(TAG, "started scenario=" + BuildConfig.SCENARIO_KIND);
        status.setText("App started successfully");
    }

    boolean verifySubmittedFlag(String input) {
        return FlagGateway.verify(this, input);
    }

    private void runBusinessTrigger(Button trigger) {
        trigger.setEnabled(false);
        status.setText("Business trigger running...");
        Thread worker = new Thread(() -> {
            BusinessTrigger.Result result = BusinessTrigger.prepare(this);
            Log.i(TAG, "business trigger result=" + result.ok
                    + " message=" + result.message
                    + " total=" + result.totalCents);
            runOnUiThread(() -> {
                stateTouches++;
                trigger.setEnabled(true);
                if (result.ok) {
                    status.setText("Business trigger ready");
                    Log.i(TAG, "business trigger ready");
                } else {
                    status.setText("Business trigger failed");
                }
            });
        }, "scenario-business-trigger");
        worker.start();
    }
}
