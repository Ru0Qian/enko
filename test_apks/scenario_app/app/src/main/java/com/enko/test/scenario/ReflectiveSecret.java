package com.enko.test.scenario;

final class ReflectiveSecret {
    private static final String[] PARTS = {
            "flag{",
            "enko",
            "_matrix",
            "_2026",
            "}",
    };

    private ReflectiveSecret() {
    }

    static String recover() {
        StringBuilder sb = new StringBuilder();
        for (String part : PARTS) {
            sb.append(part);
        }
        return sb.toString();
    }

    static boolean check(String input) {
        if (input == null) return false;
        String expected = recover();
        int diff = input.length() ^ expected.length();
        int count = Math.min(input.length(), expected.length());
        for (int i = 0; i < count; i++) {
            diff |= input.charAt(i) ^ expected.charAt(i);
        }
        return diff == 0;
    }
}
