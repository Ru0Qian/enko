package com.enko.shell;

/**
 * Public, stable runtime API exposed by the Enko shell to the hosted app (P6-1).
 *
 * <p>The shell never reaches into the protected app's code. Instead, the app
 * can <em>query</em> the current graded risk level here and decide how to
 * respond for sensitive flows, without the shell killing the process:
 *
 * <pre>{@code
 *   if (EnkoRuntime.shouldRestrict()) {
 *       // hide / disable high-value features (paid content, asset transfer...)
 *   } else if (EnkoRuntime.shouldChallenge()) {
 *       // require server-side re-verification before login / payment
 *   }
 * }</pre>
 *
 * <p>This is read-only telemetry the app opts into. It complements (does not
 * replace) server-side verification: high-value decisions (auth, payment,
 * membership, assets) must still be confirmed by the backend, with the risk
 * level used as one signal.
 *
 * <p>Kept by proguard ({@code -keep}) so the integration symbol survives R8.
 */
public final class EnkoRuntime {

    private EnkoRuntime() {
    }

    /** Current graded risk level name: ALLOW / MONITOR / CHALLENGE / RESTRICT / TERMINATE. */
    public static String riskLevel() {
        return RiskState.current().name();
    }

    /**
     * Whether the environment is risky enough that sensitive operations
     * (login, payment, license activation) should request server-side
     * re-verification before proceeding.
     */
    public static boolean shouldChallenge() {
        return RiskState.shouldChallenge();
    }

    /**
     * Whether high-value features (paid content, asset transfer, etc.) should
     * be disabled or limited because of elevated runtime risk.
     */
    public static boolean shouldRestrict() {
        return RiskState.shouldRestrict();
    }
}
