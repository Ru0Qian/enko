package com.enko.test.scenario;

import android.util.Base64;

import java.lang.reflect.Method;

public final class BusinessReflectionGate {
    private static final String CLASS_NAME_B64 =
            "Y29tLmVua28udGVzdC5zY2VuYXJpby5IaWRkZW5CdXNpbmVzc1J1bGVz";
    private static final String METHOD_NAME_B64 = "YWNjZXB0";

    boolean accept(String flag, String token, String license, int totalCents) {
        try {
            Class<?> cls = Class.forName(decode(CLASS_NAME_B64));
            Method method = cls.getDeclaredMethod(
                    decode(METHOD_NAME_B64),
                    String.class,
                    String.class,
                    String.class,
                    int.class);
            method.setAccessible(true);
            Boolean ok = (Boolean) method.invoke(null, flag, token, license, totalCents);
            return Boolean.TRUE.equals(ok);
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static String decode(String value) {
        return new String(Base64.decode(value, Base64.NO_WRAP));
    }
}
