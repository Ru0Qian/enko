package com.example.demo;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.content.ServiceConnection;
import android.graphics.Color;
import android.os.Bundle;
import android.os.IBinder;
import android.util.Log;
import android.view.Gravity;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.lang.reflect.Method;
import java.util.Map;

/**
 * Settings / diagnostics activity that exercises reflection, service binding,
 * environment inspection, and dynamic class loading.
 */
public class SettingsActivity extends Activity {
    private static final String TAG = "Settings";
    private TextView logView;
    private DemoService boundService;
    private boolean isBound;

    private final ServiceConnection conn = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            boundService = ((DemoService.LocalBinder) service).getService();
            isBound = true;
            log("Service bound: " + name.getShortClassName());
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            isBound = false;
            log("Service disconnected");
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        ScrollView scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(48, 48, 48, 48);

        TextView title = new TextView(this);
        title.setText("Diagnostics & Settings");
        title.setTextSize(24f);
        title.setTextColor(Color.parseColor("#E53935"));
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        addButton(root, "Bind Service", this::bindDemoService);
        addButton(root, "Reflection Test", this::runReflectionTest);
        addButton(root, "Environment Dump", this::dumpEnvironment);
        addButton(root, "Thread Dump", this::dumpThreads);
        addButton(root, "ClassLoader Info", this::dumpClassLoader);
        addButton(root, "Back to Main", () -> finish());

        logView = new TextView(this);
        logView.setTextSize(11f);
        logView.setTextColor(Color.DKGRAY);
        logView.setPadding(0, 24, 0, 0);
        root.addView(logView);

        scroll.addView(root);
        setContentView(scroll);
    }

    private void addButton(LinearLayout parent, String text, Runnable action) {
        Button btn = new Button(this);
        btn.setText(text);
        btn.setOnClickListener(v -> action.run());
        parent.addView(btn);
    }

    private void bindDemoService() {
        Intent intent = new Intent(this, DemoService.class);
        startService(intent);
        bindService(intent, conn, BIND_AUTO_CREATE);
        log("Binding service...");
    }

    private void runReflectionTest() {
        log("=== Reflection Test ===");
        try {
            Class<?> clz = Class.forName("com.example.demo.SecretConfig");
            java.lang.reflect.Field[] fields = clz.getDeclaredFields();
            log("SecretConfig fields: " + fields.length);
            for (java.lang.reflect.Field f : fields) {
                f.setAccessible(true);
                Object val = f.get(null);
                String s = val != null ? val.toString() : "null";
                if (s.length() > 40) s = s.substring(0, 40) + "...";
                log("  " + f.getName() + " = " + s);
            }

            // Test method invocation via reflection
            Method[] methods = CryptoHelper.class.getDeclaredMethods();
            log("CryptoHelper methods: " + methods.length);
            for (Method m : methods) {
                log("  " + m.getName() + "(" + m.getParameterCount() + " params)");
            }
        } catch (Exception e) {
            log("Reflection error: " + e.getMessage());
        }
    }

    private void dumpEnvironment() {
        log("=== Environment ===");
        log("Package: " + getPackageName());
        log("PID: " + android.os.Process.myPid());
        log("UID: " + android.os.Process.myUid());
        log("SDK: " + android.os.Build.VERSION.SDK_INT);
        log("Device: " + android.os.Build.BRAND + " " + android.os.Build.MODEL);
        log("ABI: " + String.join(", ", android.os.Build.SUPPORTED_ABIS));
        log("Data dir: " + getApplicationInfo().dataDir);
        log("Native libs: " + getApplicationInfo().nativeLibraryDir);

        try {
            String sourceDir = getApplicationInfo().sourceDir;
            long apkSize = new java.io.File(sourceDir).length();
            log("APK: " + sourceDir + " (" + apkSize + " bytes)");
        } catch (Exception e) {
            log("APK info error: " + e);
        }
    }

    private void dumpThreads() {
        log("=== Thread Dump ===");
        Map<Thread, StackTraceElement[]> threads = Thread.getAllStackTraces();
        log("Active threads: " + threads.size());
        for (Map.Entry<Thread, StackTraceElement[]> e : threads.entrySet()) {
            Thread t = e.getKey();
            log("  [" + t.getId() + "] " + t.getName()
                    + " state=" + t.getState()
                    + " daemon=" + t.isDaemon());
        }
    }

    private void dumpClassLoader() {
        log("=== ClassLoader Chain ===");
        ClassLoader cl = getClass().getClassLoader();
        int depth = 0;
        while (cl != null) {
            log("  [" + depth + "] " + cl.getClass().getName());
            cl = cl.getParent();
            depth++;
        }
        log("App classloader: " + getClassLoader().getClass().getName());
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        runOnUiThread(() -> {
            String existing = logView.getText().toString();
            if (!existing.isEmpty()) existing += "\n";
            logView.setText(existing + msg);
        });
    }

    @Override
    protected void onDestroy() {
        if (isBound) unbindService(conn);
        super.onDestroy();
    }
}
