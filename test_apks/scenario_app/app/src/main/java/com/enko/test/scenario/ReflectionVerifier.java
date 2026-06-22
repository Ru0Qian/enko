package com.enko.test.scenario;

import android.util.Base64;

import java.lang.reflect.Method;

public final class ReflectionVerifier {
    private static final String CLASS_NAME_B64 =
            "Y29tLmVua28udGVzdC5zY2VuYXJpby5SZWZsZWN0aXZlU2VjcmV0";
    private static final String RECOVER_NAME_B64 = "cmVjb3Zlcg==";
    private static final String CHECK_NAME_B64 = "Y2hlY2s=";

    public boolean verify(String input) {
        try {
            Class<?> target = Class.forName(decode(CLASS_NAME_B64));
            Method recover = target.getDeclaredMethod(decode(RECOVER_NAME_B64));
            Method check = target.getDeclaredMethod(decode(CHECK_NAME_B64), String.class);
            recover.setAccessible(true);
            check.setAccessible(true);
            String expected = (String)recover.invoke(null);
            Boolean checked = (Boolean)check.invoke(null, input);
            return input.equals(expected) && Boolean.TRUE.equals(checked);
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static String decode(String value) {
        return new String(Base64.decode(value, Base64.NO_WRAP));
    }
}
