package com.enko.test.scenario;

public final class NativeScenarioVerifier {
    static {
        System.loadLibrary("scenario_native");
    }

    public boolean verify(String input) {
        if (input == null) {
            return false;
        }
        return nativeVerify(input);
    }

    public int businessScore(String input, int totalCents, String sessionToken) {
        if (input == null || sessionToken == null) {
            return -1;
        }
        return nativeBusinessScore(input, totalCents, sessionToken);
    }

    private static native boolean nativeVerify(String input);

    private static native int nativeBusinessScore(String input, int totalCents, String sessionToken);
}
