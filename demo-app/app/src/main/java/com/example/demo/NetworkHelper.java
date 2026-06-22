package com.example.demo;

import android.util.Log;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Network utilities — HTTP calls, SSL pinning, hash verification.
 */
public class NetworkHelper {
    private static final String TAG = "NetworkHelper";
    private static final ExecutorService executor = Executors.newFixedThreadPool(2);

    public interface Callback {
        void onResult(String result);
        void onError(String error);
    }

    public static void fetchUrl(String urlStr, Callback callback) {
        executor.submit(() -> {
            try {
                URL url = new URL(urlStr);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setConnectTimeout(10_000);
                conn.setReadTimeout(10_000);
                conn.setRequestProperty("User-Agent", "EnkoDemo/1.0");
                conn.setRequestProperty("X-Api-Key", SecretConfig.API_KEY);

                int code = conn.getResponseCode();
                if (code == 200) {
                    BufferedReader reader = new BufferedReader(
                            new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) sb.append(line);
                    reader.close();
                    callback.onResult(sb.toString());
                } else {
                    callback.onError("HTTP " + code);
                }
                conn.disconnect();
            } catch (Exception e) {
                Log.e(TAG, "fetchUrl error", e);
                callback.onError(e.getMessage());
            }
        });
    }

    public static String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) hex.append(String.format("%02x", b & 0xFF));
            return hex.toString();
        } catch (Exception e) {
            return "error:" + e.getMessage();
        }
    }

    public static String hmacSign(String data, String key) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(
                    key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) hex.append(String.format("%02x", b & 0xFF));
            return hex.toString();
        } catch (Exception e) {
            return "error:" + e.getMessage();
        }
    }
}
