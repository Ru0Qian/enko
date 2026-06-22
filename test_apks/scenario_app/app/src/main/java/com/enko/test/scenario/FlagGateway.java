package com.enko.test.scenario;

import android.content.Context;

public final class FlagGateway {
    private FlagGateway() {
    }

    public static boolean verify(Context context, String input) {
        if (input == null || input.length() < 10) {
            return false;
        }
        String scenario = BuildConfig.SCENARIO_KIND;
        if ("java-basic".equals(scenario)) {
            return new JavaBasicVerifier().verify(input);
        }
        if ("reflection".equals(scenario)) {
            return new ReflectionVerifier().verify(input);
        }
        if ("native-jni".equals(scenario)) {
            return new NativeScenarioVerifier().verify(input);
        }
        if ("resource-state".equals(scenario)) {
            return new ResourceScenarioVerifier(context).verify(input);
        }
        if ("complex-business".equals(scenario)) {
            return new ComplexBusinessVerifier(context).verify(input);
        }
        return false;
    }
}
