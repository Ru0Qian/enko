package com.enko.test.scenario;

import android.content.Context;
import android.content.SharedPreferences;

public final class BusinessTrigger {
    private static final String PREFS = "business_trigger_state";
    private static final String KEY_ISSUED_AT = "issued_at";
    private static final String KEY_TOTAL = "total";
    private static final String KEY_STABILITY = "stability";
    private static final String KEY_NATIVE_SCORE = "native_score";
    private static final String KEY_PROOF = "proof";
    private static final String KEY_CONSUMED = "consumed";
    private static final String TRIGGER_ACCOUNT = "acct-trigger-2026";
    private static final String TRIGGER_SEED = "business-trigger-flow";
    private static final long MAX_AGE_MS = 5 * 60 * 1000L;

    public static final class Result {
        public final boolean ok;
        public final String message;
        public final int totalCents;

        private Result(boolean ok, String message, int totalCents) {
            this.ok = ok;
            this.message = message;
            this.totalCents = totalCents;
        }
    }

    private static final class Snapshot {
        final PricingEngine.Quote quote;
        final int stability;
        final String license;
        final String token;
        final int nativeScore;

        Snapshot(PricingEngine.Quote quote, int stability, String license, String token, int nativeScore) {
            this.quote = quote;
            this.stability = stability;
            this.license = license;
            this.token = token;
            this.nativeScore = nativeScore;
        }
    }

    private BusinessTrigger() {
    }

    public static Result prepare(Context context) {
        try {
            Context app = context.getApplicationContext();
            Snapshot snapshot = buildSnapshot(app);
            if (snapshot.quote.totalCents != 7202 || snapshot.stability != 252011) {
                return new Result(false, "trigger quote mismatch", snapshot.quote.totalCents);
            }
            if (snapshot.nativeScore <= 0) {
                return new Result(false, "trigger native mismatch", snapshot.quote.totalCents);
            }

            long issuedAt = System.currentTimeMillis();
            String proof = buildProof(app, snapshot, issuedAt);
            prefs(app).edit()
                    .putLong(KEY_ISSUED_AT, issuedAt)
                    .putInt(KEY_TOTAL, snapshot.quote.totalCents)
                    .putInt(KEY_STABILITY, snapshot.stability)
                    .putInt(KEY_NATIVE_SCORE, snapshot.nativeScore)
                    .putString(KEY_PROOF, proof)
                    .putBoolean(KEY_CONSUMED, false)
                    .apply();
            return new Result(true, "business trigger ready", snapshot.quote.totalCents);
        } catch (Throwable t) {
            return new Result(false, "trigger failed: " + t.getClass().getSimpleName(), 0);
        }
    }

    public static boolean consume(Context context) {
        try {
            Context app = context.getApplicationContext();
            SharedPreferences p = prefs(app);
            if (p.getBoolean(KEY_CONSUMED, true)) {
                return false;
            }
            long issuedAt = p.getLong(KEY_ISSUED_AT, 0L);
            if (issuedAt <= 0L || System.currentTimeMillis() - issuedAt > MAX_AGE_MS) {
                return false;
            }

            Snapshot snapshot = buildSnapshot(app);
            if (p.getInt(KEY_TOTAL, -1) != snapshot.quote.totalCents
                    || p.getInt(KEY_STABILITY, -1) != snapshot.stability
                    || p.getInt(KEY_NATIVE_SCORE, -1) != snapshot.nativeScore) {
                return false;
            }

            String expected = buildProof(app, snapshot, issuedAt);
            String stored = p.getString(KEY_PROOF, "");
            if (!constantTimeEquals(stored, expected)) {
                return false;
            }

            p.edit().putBoolean(KEY_CONSUMED, true).apply();
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static Snapshot buildSnapshot(Context context) {
        InventoryDatabase db = new InventoryDatabase(context);
        BusinessOrder order = db.buildOrder();
        PricingEngine pricing = new PricingEngine();
        PricingEngine.Quote quote = pricing.quote(order);
        int stability = pricing.stabilityCode(quote);

        ResourceLicense resourceLicense = new ResourceLicense();
        String license = resourceLicense.readLicense(context);
        if (!resourceLicense.verifyLicense(license)) {
            throw new IllegalStateException("bad license");
        }

        BusinessSession session = new BusinessSession();
        String token = session.issueToken(context, TRIGGER_ACCOUNT, TRIGGER_SEED);
        if (!session.isFresh(token)) {
            throw new IllegalStateException("stale trigger token");
        }

        int nativeScore = new NativeScenarioVerifier().businessScore(
                "trigger:" + license,
                quote.totalCents,
                token);
        return new Snapshot(quote, stability, license, token, nativeScore);
    }

    private static String buildProof(Context context, Snapshot snapshot, long issuedAt) {
        String material = context.getPackageName()
                + ":" + snapshot.quote.totalCents
                + ":" + snapshot.stability
                + ":" + snapshot.license
                + ":" + snapshot.token
                + ":" + snapshot.nativeScore
                + ":" + issuedAt;
        String digest = BusinessSession.sha256(material);
        if (digest.length() < 32) {
            return digest;
        }
        return digest.substring(0, 32);
    }

    private static SharedPreferences prefs(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private static boolean constantTimeEquals(String left, String right) {
        if (left == null || right == null) {
            return false;
        }
        int diff = left.length() ^ right.length();
        int count = Math.min(left.length(), right.length());
        for (int i = 0; i < count; i++) {
            diff |= left.charAt(i) ^ right.charAt(i);
        }
        return diff == 0;
    }
}
