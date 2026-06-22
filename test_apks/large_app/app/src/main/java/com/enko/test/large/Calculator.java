package com.enko.test.large;

public class Calculator {
    public static String compute(String operation, int n) {
        switch (operation) {
            case "fib": return String.valueOf(fibonacci(n));
            case "fact": return String.valueOf(factorial(n));
            default: return "unknown op";
        }
    }

    private static long fibonacci(int n) {
        if (n <= 1) return n;
        long a = 0, b = 1;
        for (int i = 2; i <= n; i++) {
            long tmp = a + b; a = b; b = tmp;
        }
        return b;
    }

    private static long factorial(int n) {
        long result = 1;
        for (int i = 2; i <= n; i++) result *= i;
        return result;
    }
}
