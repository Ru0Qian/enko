package com.example.demo;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.util.Log;
import android.view.Gravity;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

public class MainActivity extends Activity {
    private static final String TAG = "EnkoDemo";
    private LicenseManager licenseManager;
    private TextView statusText;
    private TextView infoText;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        licenseManager = new LicenseManager(this);

        ScrollView scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(48, 48, 48, 48);

        // Title
        TextView title = new TextView(this);
        title.setText("Enko Demo App");
        title.setTextSize(28f);
        title.setTextColor(Color.parseColor("#1E88E5"));
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        // Subtitle
        TextView subtitle = new TextView(this);
        subtitle.setText("Protected by Enko DEX Hardening");
        subtitle.setTextSize(14f);
        subtitle.setTextColor(Color.GRAY);
        subtitle.setGravity(Gravity.CENTER);
        subtitle.setPadding(0, 8, 0, 32);
        root.addView(subtitle);

        // Status
        statusText = new TextView(this);
        statusText.setTextSize(16f);
        statusText.setPadding(0, 16, 0, 24);
        updateStatus();
        root.addView(statusText);

        // License input
        EditText licenseInput = new EditText(this);
        licenseInput.setHint("Enter license key: ENKO-XXXX-YYYY-ZZZZ-WWWW");
        licenseInput.setSingleLine(true);
        root.addView(licenseInput);

        // Activate button
        addButton(root, "Activate License", () -> {
            String key = licenseInput.getText().toString().trim();
            if (licenseManager.validateLicense(key)) {
                Toast.makeText(this, "License activated!", Toast.LENGTH_SHORT).show();
                updateStatus();
            } else {
                Toast.makeText(this, "Invalid license key", Toast.LENGTH_SHORT).show();
            }
        });

        addButton(root, "Run Crypto Test", this::runCryptoTest);

        addButton(root, "Call Secret API (Premium)", () -> {
            if (!licenseManager.isActivated()) {
                Toast.makeText(this, "Premium feature — activate license first", Toast.LENGTH_SHORT).show();
                return;
            }
            String result = PremiumFeature.callSecretApi(SecretConfig.API_KEY);
            appendInfo("API Response: " + result);
        });

        addButton(root, "Device Fingerprint (Premium)", () -> {
            if (!licenseManager.isActivated()) {
                Toast.makeText(this, "Premium feature — activate license first", Toast.LENGTH_SHORT).show();
                return;
            }
            String fp = PremiumFeature.getDeviceFingerprint(this);
            appendInfo("Fingerprint: " + fp);
        });

        addButton(root, "Network Hash Test", this::runNetworkHashTest);

        addButton(root, "Start Background Service", () -> {
            Intent svc = new Intent(this, DemoService.class);
            startService(svc);
            Toast.makeText(this, "Service started", Toast.LENGTH_SHORT).show();
            appendInfo("Background service started (check logcat for heartbeats)");
        });

        addButton(root, "Diagnostics / Settings", () ->
                startActivity(new Intent(this, SettingsActivity.class)));

        // Info area
        infoText = new TextView(this);
        infoText.setTextSize(12f);
        infoText.setTextColor(Color.DKGRAY);
        infoText.setPadding(0, 24, 0, 0);
        root.addView(infoText);

        scroll.addView(root);
        setContentView(scroll);

        Log.i(TAG, "MainActivity created, backend=" + SecretConfig.BACKEND_URL);
    }

    private void addButton(LinearLayout parent, String text, Runnable action) {
        Button btn = new Button(this);
        btn.setText(text);
        btn.setOnClickListener(v -> action.run());
        parent.addView(btn);
    }

    private void updateStatus() {
        statusText.setText(licenseManager.getStatusText());
    }

    private void runCryptoTest() {
        CryptoHelper crypto = new CryptoHelper();
        String original = "Sensitive user data #12345";
        String encrypted = crypto.encrypt(original);
        String decrypted = crypto.decrypt(encrypted);
        appendInfo("Encrypt/Decrypt test:\n  Original: " + original
                 + "\n  Encrypted: " + encrypted
                 + "\n  Decrypted: " + decrypted);
    }

    private void runNetworkHashTest() {
        String data = "test_payload_" + System.currentTimeMillis();
        String sha = NetworkHelper.sha256(data);
        String hmac = NetworkHelper.hmacSign(data, SecretConfig.AES_KEY_HEX);
        appendInfo("Hash test:\n  Data: " + data
                 + "\n  SHA-256: " + sha
                 + "\n  HMAC: " + hmac);
    }

    private void appendInfo(String msg) {
        String existing = infoText.getText().toString();
        if (!existing.isEmpty()) existing += "\n\n";
        infoText.setText(existing + msg);
    }
}
