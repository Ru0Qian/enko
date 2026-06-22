package com.enko.shell;

/**
 * Graded runtime-risk response policy (P6-1).
 *
 * <p>Maps a native risk {@link NativeRiskEvaluator.Decision} plus the build's
 * {@link RuntimeConfig} onto one of five escalating actions, instead of the
 * old binary "block -> kill" decision. This implements the commercial response
 * matrix:
 *
 * <ul>
 *   <li>low risk    -> {@link Action#MONITOR}  (record only, never kill)</li>
 *   <li>medium risk -> {@link Action#CHALLENGE} (continue; sensitive ops should
 *       be re-verified, ideally server-side)</li>
 *   <li>high risk   -> {@link Action#RESTRICT} (continue; restrict high-value
 *       features)</li>
 *   <li>critical    -> {@link Action#TERMINATE} (block / kill the process)</li>
 * </ul>
 *
 * <p><b>Key commercial guarantee:</b> {@link Action#TERMINATE} is only reachable
 * under the {@code strict} profile or {@code commercialMode}. Under
 * {@code balanced}/{@code compat} the response is capped at {@link Action#RESTRICT}
 * even when the runtime policy is {@code block}, so real users on rooted phones,
 * emulators or behind a proxy are not killed by default. Termination must be an
 * explicit, deliberate choice.
 *
 * <p>This class is pure logic with no Android dependencies so it can be reasoned
 * about and unit-tested in isolation.
 */
final class RiskResponsePolicy {

    /** Escalating responses, ordered least -> most severe. */
    enum Action {
        ALLOW,      // no risk signal
        MONITOR,    // log only, continue normally
        CHALLENGE,  // continue, but sensitive operations should re-verify
        RESTRICT,   // continue, but high-value features must be limited
        TERMINATE   // block / kill the process
    }

    // Native score (0-100) thresholds for the base tier.
    static final int SCORE_MEDIUM = 40;
    static final int SCORE_HIGH = 70;
    static final int SCORE_CRITICAL = 90;

    private RiskResponsePolicy() {
    }

    /**
     * Decide the graded response for a risk decision under the given config.
     *
     * @param cfg      runtime config (policy + profile + commercial flag)
     * @param decision native risk evaluation result
     * @return the action the shell should take
     */
    static Action decide(RuntimeConfig cfg, NativeRiskEvaluator.Decision decision) {
        if (decision == null || decision.signalCount == 0) {
            return Action.ALLOW;
        }
        if (cfg == null) {
            return Action.MONITOR;
        }
        if (cfg.isOffPolicy()) {
            return Action.ALLOW;
        }

        Action base = baseTier(decision);
        Action capped = lessSevere(base, policyCap(cfg));

        // Process termination is opt-in: only strict profile or commercial mode
        // may actually kill. balanced/compat degrade to RESTRICT instead, so the
        // default posture never kills real users.
        if (capped == Action.TERMINATE && !allowsTermination(cfg)) {
            return Action.RESTRICT;
        }
        return capped;
    }

    /** True when the config is permitted to terminate the process on risk. */
    static boolean allowsTermination(RuntimeConfig cfg) {
        if (cfg == null) {
            return false;
        }
        return cfg.commercialMode || RuntimeConfig.PROFILE_STRICT.equals(cfg.riskProfile);
    }

    /** Base severity derived from the native score and high-confidence signals. */
    private static Action baseTier(NativeRiskEvaluator.Decision d) {
        if (d.highConfidenceCount >= 2 || d.score >= SCORE_CRITICAL) {
            return Action.TERMINATE;
        }
        if (d.highConfidenceCount >= 1 || d.score >= SCORE_HIGH) {
            return Action.RESTRICT;
        }
        if (d.score >= SCORE_MEDIUM) {
            return Action.CHALLENGE;
        }
        return Action.MONITOR;
    }

    /** The most severe action a given runtime policy is allowed to produce. */
    private static Action policyCap(RuntimeConfig cfg) {
        String policy = cfg.riskPolicy;
        if (RuntimeConfig.POLICY_OFF.equals(policy)) {
            return Action.ALLOW;
        }
        if (RuntimeConfig.POLICY_LOG.equals(policy)) {
            return Action.MONITOR;
        }
        if (RuntimeConfig.POLICY_WARN.equals(policy)) {
            return Action.CHALLENGE;
        }
        if (RuntimeConfig.POLICY_DEGRADE.equals(policy)) {
            return Action.RESTRICT;
        }
        // POLICY_BLOCK
        return Action.TERMINATE;
    }

    /** Return the less severe (lower-ordinal) of two actions. */
    private static Action lessSevere(Action a, Action b) {
        return a.ordinal() <= b.ordinal() ? a : b;
    }
}
