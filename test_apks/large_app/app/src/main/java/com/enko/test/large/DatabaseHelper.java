package com.enko.test.large;

public class DatabaseHelper {
    private static boolean initialized = false;
    private static int recordCount = 0;

    public static void init() {
        if (!initialized) {
            initialized = true;
            recordCount = 42;
        }
    }

    public static String getStatus() {
        init();
        return initialized ? "OK (" + recordCount + " records)" : "NOT INIT";
    }
}
