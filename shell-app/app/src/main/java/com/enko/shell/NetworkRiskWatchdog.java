package com.enko.shell;

import android.content.Context;
import android.util.Log;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;

/**
 * Background watchdog that periodically re-runs runtime risk detection.
 *
 * <p>Catches scenarios where a risky environment appears after app startup.
 * In block policy it now follows a two-step strategy: first hit enters
 * degraded mode with delayed terminate; persistent hit terminates immediately.
 */
final class NetworkRiskWatchdog {
    private static final String TAG = "EnkoShell";
    private static final long CHECK_INTERVAL_MS = 8_000; // 8 seconds
    private static final long BLOCK_KILL_DELAY_MS = 3_500; // first-hit delayed terminate

    private static volatile Thread sThread;

    private NetworkRiskWatchdog() {
    }

    /**
     * Start the watchdog. Safe to call multiple times; only one thread runs.
     */
    static synchronized void start(Context context, RuntimeConfig cfg) {
        if (cfg == null) {
            return;
        }
        if (sThread != null && sThread.isAlive()) {
            return;
        }

        /*
         * During attachBaseContext(), getApplicationContext() may return null.
         * Use the context directly; ContextImpl is held by framework lifetime.
         */
        Context appCtx = context.getApplicationContext();
        final WeakReference<Context> ctxRef = new WeakReference<>(appCtx != null ? appCtx : context);

        sThread = new Thread(new Runnable() {
            @Override
            public void run() {
                int consecutiveBlockHits = 0;
                boolean delayedKillScheduled = false;

                Log.i(TAG, "runtime risk watchdog started (interval="
                        + CHECK_INTERVAL_MS + "ms, policy="
                        + (cfg.shouldBlockOnRisk() ? "block" : "log") + ", profile="
                        + cfg.riskProfile + ")");

                while (!Thread.currentThread().isInterrupted()) {
                    try {
                        Thread.sleep(CHECK_INTERVAL_MS);
                    } catch (InterruptedException e) {
                        break;
                    }

                    Context ctx = ctxRef.get();
                    if (ctx == null) {
                        break;
                    }

                    List<String> reasons;
                    try {
                        reasons = detectRuntimeRisk(ctx, cfg);
                    } catch (Throwable t) {
                        Log.w(TAG, "watchdog check failed", t);
                        continue;
                    }

                    if (reasons.isEmpty()) {
                        consecutiveBlockHits = 0;
                        RiskState.clear();
                        continue;
                    }

                    String joined;
                    NativeRiskEvaluator.Decision decision;
                    try {
                        joined = NativeRiskEvaluator.joinReasons(reasons);
                        decision = NativeRiskEvaluator.evaluate(cfg, reasons);
                    } catch (SecurityException e) {
                        reasons = new ArrayList<>(reasons);
                        reasons.add("native-risk-evaluator-failed");
                        joined = NativeRiskEvaluator.joinReasons(reasons);
                        decision = new NativeRiskEvaluator.Decision(100, reasons.size(), 1, true);
                        Log.e(TAG, "watchdog: native evaluator failed, force block", e);
                    }

                    // P6-1: graded response. Only TERMINATE (strict/commercial)
                    // escalates to a kill; RESTRICT/CHALLENGE/MONITOR keep the
                    // process alive and just raise the shared risk level.
                    RiskResponsePolicy.Action action =
                            RiskResponsePolicy.decide(cfg, decision);
                    RiskState.escalate(action);

                    if (action == RiskResponsePolicy.Action.TERMINATE) {
                        consecutiveBlockHits++;
                        if (consecutiveBlockHits == 1) {
                            Log.e(TAG, "watchdog: risk detected, entering degraded mode (delayed terminate): "
                                    + joined + " (profile=" + cfg.riskProfile
                                    + ",score=" + decision.score
                                    + ",high=" + decision.highConfidenceCount + ")");
                            if (!delayedKillScheduled) {
                                delayedKillScheduled = true;
                                scheduleDelayedKill(joined, cfg, decision);
                            }
                            continue;
                        }

                        Log.e(TAG, "watchdog: risk persisted, terminate now: " + joined
                                + " (profile=" + cfg.riskProfile
                                + ",score=" + decision.score
                                + ",high=" + decision.highConfidenceCount + ")");
                        killNow();
                    } else {
                        consecutiveBlockHits = 0;
                        Log.w(TAG, "watchdog: risk detected (" + action + "): " + joined
                                + " (profile=" + cfg.riskProfile
                                + ",score=" + decision.score
                                + ",high=" + decision.highConfidenceCount + ")");
                    }
                }
                Log.i(TAG, "runtime risk watchdog stopped");
            }
        }, "pool-exec-1");  /* Disguised thread name */
        sThread.setDaemon(true);
        sThread.setPriority(Thread.MIN_PRIORITY);
        sThread.start();
    }

    private static List<String> detectRuntimeRisk(Context ctx, RuntimeConfig cfg) {
        List<String> reasons = new ArrayList<>();
        reasons.addAll(NetworkRiskDetector.detectNetworkRisk(ctx, cfg.blockProxyVpn));

        if (!NativeBridge.isAvailable()) {
            reasons.add("native-bridge-unavailable");
            return reasons;
        }
        IntegrityGate.collectNativeRiskReasons(cfg, reasons);

        /* Java-layer hook detection in watchdog cycle. */
        reasons.addAll(JavaHookDetector.detect());

        return reasons;
    }

    private static void scheduleDelayedKill(
            final String reason,
            final RuntimeConfig cfg,
            final NativeRiskEvaluator.Decision decision
    ) {
        Thread delayedTerminator = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Thread.sleep(BLOCK_KILL_DELAY_MS);
                } catch (InterruptedException ignored) {
                    // Continue.
                }
                Log.e(TAG, "watchdog: delayed terminate on risk: " + reason
                        + " (profile=" + cfg.riskProfile
                        + ",score=" + decision.score
                        + ",high=" + decision.highConfidenceCount + ")");
                killNow();
            }
        }, "async-task-2");  /* Disguised thread name */
        delayedTerminator.setDaemon(true);
        delayedTerminator.start();
    }

    private static void killNow() {
        android.os.Process.killProcess(android.os.Process.myPid());
        System.exit(10);
        Runtime.getRuntime().halt(10);
    }
}
