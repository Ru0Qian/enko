package com.enko.shell;

import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Detects Java-layer hook frameworks (Xposed, LSPosed, EdXposed, etc.).
 *
 * <p>Detection strategies:
 * <ol>
 *   <li>Stack trace scanning — hooks inject frames from known packages.</li>
 *   <li>/proc/self/maps scanning — hook framework .so files in memory.</li>
 *   <li>ClassLoader probing — attempt to load known hook framework classes.</li>
 *   <li>System property checks — ro.xposed.version, etc.</li>
 *   <li>File existence checks — common framework installation paths.</li>
 * </ol>
 */
final class JavaHookDetector {
    private static final String TAG = "EnkoShell";

    private JavaHookDetector() {
    }

    /**
     * Run all Java hook detection checks.
     *
     * @return list of detected risk reasons (empty if clean)
     */
    static List<String> detect() {
        List<String> reasons = new ArrayList<>();

        if (checkStackTraces()) {
            reasons.add("xposed-stack-detected");
        }
        if (checkMapsForHookLibs()) {
            reasons.add("hook-lib-in-maps");
        }
        if (checkHookClassesLoadable()) {
            reasons.add("hook-classes-loadable");
        }
        if (checkHookSystemProperties()) {
            reasons.add("hook-sysprop-detected");
        }
        if (checkHookFilePaths()) {
            reasons.add("hook-file-detected");
        }

        return reasons;
    }

    /**
     * Scan all thread stack traces for frames from known hook frameworks.
     * Xposed/LSPosed inject calls through packages like:
     *   de.robv.android.xposed, io.github.lsposed, ...
     */
    private static boolean checkStackTraces() {
        try {
            Map<Thread, StackTraceElement[]> allTraces = Thread.getAllStackTraces();
            for (StackTraceElement[] trace : allTraces.values()) {
                for (StackTraceElement frame : trace) {
                    String cls = frame.getClassName();
                    if (cls == null) continue;
                    if (cls.contains("de.robv.android.xposed")
                            || cls.contains("io.github.lsposed")
                            || cls.contains("org.lsposed.lspatch")
                            || cls.contains("com.elderdrivers.riru")
                            || cls.contains("org.lsposed")
                            || cls.contains("com.android.internal.os.ZygoteInit")
                                && cls.contains("xposed")) {
                        return true;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    /**
     * Scan /proc/self/maps for hook framework native libraries.
     */
    private static boolean checkMapsForHookLibs() {
        String[] hookLibs = {
                "libxposed_art",
                "liblspd",
                "libzygisk",
                "liblspatch",
                "libriru",
                "libsubstrate",
                "libwhale",
                "libsandhook",
                "libepic",
                "libpine",
                "libdobby",
        };
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String lower = line.toLowerCase();
                for (String lib : hookLibs) {
                    if (lower.contains(lib)) {
                        return true;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    /**
     * Try to load known hook framework classes via the current ClassLoader.
     * If any are loadable, a hook framework is present in the process.
     */
    private static boolean checkHookClassesLoadable() {
        String[] hookClasses = {
                "de.robv.android.xposed.XposedBridge",
                "de.robv.android.xposed.XposedHelpers",
                "io.github.lsposed.lspd.core.Main",
                "org.lsposed.lspd.core.Main",
                "org.lsposed.lspatch.LSPApplication",
                "com.saurik.substrate.MS",
                "com.swift.sandhook.SandHook",
                "top.canyie.pine.Pine",
                "me.weishu.epic.art.Epic",
        };
        for (String cls : hookClasses) {
            try {
                Class.forName(cls, false, ClassLoader.getSystemClassLoader());
                return true;
            } catch (ClassNotFoundException ignored) {
            }
            try {
                Class.forName(cls);
                return true;
            } catch (ClassNotFoundException ignored) {
            }
        }
        return false;
    }

    /**
     * Check system properties that hook frameworks set.
     */
    private static boolean checkHookSystemProperties() {
        String[] props = {
                "ro.xposed.version",
                "persist.riru.version",
                "persist.lsposed.version",
                "persist.sys.lspatch.version",
        };
        for (String prop : props) {
            try {
                String val = (String) Class.forName("android.os.SystemProperties")
                        .getDeclaredMethod("get", String.class)
                        .invoke(null, prop);
                if (val != null && !val.isEmpty()) {
                    return true;
                }
            } catch (Throwable ignored) {
            }
        }
        return false;
    }

    /**
     * Check filesystem for known hook framework installation paths.
     */
    private static boolean checkHookFilePaths() {
        String[] paths = {
                "/system/framework/XposedBridge.jar",
                "/system/lib/libxposed_art.so",
                "/system/lib64/libxposed_art.so",
                "/data/adb/lspd",
                "/data/adb/riru",
                "/data/adb/modules/lsposed",
                "/data/adb/modules/riru-lsposed",
                "/data/adb/modules/riru_lsposed",
                "/data/adb/modules/zygisk-lsposed",
                "/data/adb/modules/zygisk_lsposed",
                "/data/adb/modules/edxposed",
                "/data/local/tmp/lspatch",
        };
        for (String path : paths) {
            if (new File(path).exists()) {
                return true;
            }
        }
        return false;
    }
}
