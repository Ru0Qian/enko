package com.enko.test.small;

import android.app.Activity;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.util.Log;

public class MainActivity extends Activity {
    private static final String TAG = "SmallMain";
    private int clickCount = 0;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Log.i(TAG, "onCreate");

        TextView status = findViewById(R.id.status);
        EditText flagInput = findViewById(R.id.flagInput);

        Button btn = findViewById(R.id.btn);
        btn.setOnClickListener(v -> {
            clickCount++;
            status.setText("Clicked: " + clickCount + " times");
            Log.d(TAG, "Button clicked: " + clickCount);
        });

        Button btnVerify = findViewById(R.id.btnVerify);
        btnVerify.setOnClickListener(v -> {
            String input = flagInput.getText().toString().trim();
            boolean correct = verifySubmittedFlag(input);
            if (correct) {
                status.setText("*** CORRECT! Flag accepted. ***");
            } else {
                status.setText("Incorrect flag, try again.");
            }
        });

        status.setText("App started successfully");
    }

    // Verifies user-submitted flag
    // Package-private so ART RegisterNatives passes `this` correctly
    boolean verifySubmittedFlag(String input) {
        if (input == null || input.isEmpty()) return false;
        if (input.length() < 10) return false;

        Log.d(TAG, "deriveKey=" + hex(FlagChecker.deriveKey()));

        // Call the flag checker methods (these become VMP/extract targets)
        String realFlag = FlagChecker.recoverFlag();
        byte[] expectedHash = FlagChecker.expectedFlagHash();

        // Compare submitted flag against the real flag
        if (!input.equals(realFlag)) {
            Log.d(TAG, "Flag mismatch, input length=" + input.length()
                    + ", realFlag=" + realFlag + ", real length=" + realFlag.length());
            return false;
        }

        // Also verify hash for extra assurance
        byte[] inputBytes = input.getBytes();
        boolean hashOk = FlagChecker.verifyHash(inputBytes, expectedHash);
        Log.i(TAG, "Hash verification: " + hashOk);
        return hashOk;
    }

    private static String hex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }

    @Override
    protected void onResume() {
        super.onResume();
        Log.i(TAG, "onResume");
    }
}
