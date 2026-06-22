package com.enko.test.scenario;

import android.content.Context;
import android.util.Log;

public final class ComplexBusinessVerifier {
    private static final String TAG = "BusinessVerifier";
    private static final int[] ENCODED_FLAG = {
            36, 35, 61, 14, 13, 230, 254, 246, 197, 232, 166,
            164, 173, 130, 150, 96, 97, 108, 115, 84, 39, 39,
            18, 4, 2, 216, 166, 145, 156, 141, 181,
    };

    private final Context context;

    ComplexBusinessVerifier(Context context) {
        this.context = context.getApplicationContext();
    }

    public boolean verify(String input) {
        if (input == null || input.length() < 20) {
            return false;
        }

        String expected = recoverFlag();
        if (!constantTimeEquals(input, expected)) {
            Log.i(TAG, "stage=flag result=false inputLen=" + input.length() + " expectedLen=" + expected.length());
            return false;
        }
        Log.i(TAG, "stage=flag result=true");

        if (!BusinessTrigger.consume(context)) {
            Log.i(TAG, "stage=trigger result=false");
            return false;
        }
        Log.i(TAG, "stage=trigger result=true");

        InventoryDatabase db = new InventoryDatabase(context);
        BusinessOrder order = db.buildOrder();
        PricingEngine pricing = new PricingEngine();
        PricingEngine.Quote quote = pricing.quote(order);
        if (quote.totalCents != 7202 || pricing.stabilityCode(quote) != 252011) {
            Log.i(TAG, "stage=quote result=false total=" + quote.totalCents
                    + " stability=" + pricing.stabilityCode(quote));
            return false;
        }
        Log.i(TAG, "stage=quote result=true total=" + quote.totalCents);

        ResourceLicense resourceLicense = new ResourceLicense();
        String license = resourceLicense.readLicense(context);
        if (!resourceLicense.verifyLicense(license)) {
            Log.i(TAG, "stage=license result=false len=" + license.length());
            return false;
        }
        Log.i(TAG, "stage=license result=true");

        BusinessSession session = new BusinessSession();
        String token = session.issueToken(context, "acct-2026", input);
        if (!session.isFresh(token)) {
            Log.i(TAG, "stage=session result=false tokenLen=" + token.length());
            return false;
        }
        Log.i(TAG, "stage=session result=true tokenLen=" + token.length());

        if (!new BusinessReflectionGate().accept(input, token, license, quote.totalCents)) {
            Log.i(TAG, "stage=reflection result=false");
            return false;
        }
        Log.i(TAG, "stage=reflection result=true");

        int nativeScore = new NativeScenarioVerifier().businessScore(input, quote.totalCents, token);
        int expectedNativeScore = nativeScoreReference(input, quote.totalCents, token);
        Log.i(TAG, "stage=native result=" + (nativeScore == expectedNativeScore)
                + " native=" + nativeScore + " expected=" + expectedNativeScore);
        return nativeScore == expectedNativeScore;
    }

    public String recoverFlag() {
        char[] out = new char[ENCODED_FLAG.length];
        for (int i = 0; i < ENCODED_FLAG.length; i++) {
            out[i] = (char)(ENCODED_FLAG[i] ^ ((0x42 + i * 13) & 0xFF));
        }
        return new String(out);
    }

    public boolean constantTimeEquals(String left, String right) {
        int diff = left.length() ^ right.length();
        int count = Math.min(left.length(), right.length());
        for (int i = 0; i < count; i++) {
            diff |= left.charAt(i) ^ right.charAt(i);
        }
        return diff == 0;
    }

    public int nativeScoreReference(String input, int totalCents, String token) {
        long acc = (0x811C9DC5L ^ totalCents) & 0xFFFFFFFFL;
        for (int i = 0; i < input.length(); i++) {
            acc ^= input.charAt(i) & 0xFF;
            acc = (acc * 16777619L) & 0xFFFFFFFFL;
        }
        for (int i = 0; i < token.length(); i++) {
            acc ^= token.charAt(i) & 0xFF;
            acc = (acc * 16777619L) & 0xFFFFFFFFL;
        }
        return (int)(acc & 0x7FFFFFFFL);
    }
}
