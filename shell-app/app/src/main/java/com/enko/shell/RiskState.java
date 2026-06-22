package com.enko.shell;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Process-wide current risk level (P6-1).
 *
 * <p>The graded risk policy ({@link RiskResponsePolicy}) updates this on every
 * enforcement pass. The real app (or shell-protected payload flows) can read it
 * to drive graded responses without killing the process:
 *
 * <ul>
 *   <li>{@link RiskResponsePolicy.Action#CHALLENGE} -- sensitive operations
 *       (login, payment, license activation) should request server-side
 *       re-verification.</li>
 *   <li>{@link RiskResponsePolicy.Action#RESTRICT} -- high-value features should
 *       be disabled or limited.</li>
 * </ul>
 *
 * <p>Only ever escalates within a single risk episode; it is reset to ALLOW when
 * a detection pass comes back clean. Holds an ordinal (not the enum) in an
 * {@link AtomicInteger} so it is cheap and lock-free to read from any thread.
 */
final class RiskState {

    private static final AtomicInteger sLevel =
            new AtomicInteger(RiskResponsePolicy.Action.ALLOW.ordinal());

    private RiskState() {
    }

    /** Current graded risk action. */
    static RiskResponsePolicy.Action current() {
        return RiskResponsePolicy.Action.values()[sLevel.get()];
    }

    /** Raise the level to {@code action} if it is more severe than the current. */
    static void escalate(RiskResponsePolicy.Action action) {
        if (action == null) {
            return;
        }
        int target = action.ordinal();
        int cur;
        do {
            cur = sLevel.get();
            if (target <= cur) {
                return;
            }
        } while (!sLevel.compareAndSet(cur, target));
    }

    /** Reset to ALLOW after a clean detection pass. */
    static void clear() {
        sLevel.set(RiskResponsePolicy.Action.ALLOW.ordinal());
    }

    /** Whether sensitive operations should request extra (server-side) verification. */
    static boolean shouldChallenge() {
        return sLevel.get() >= RiskResponsePolicy.Action.CHALLENGE.ordinal();
    }

    /** Whether high-value features should be restricted. */
    static boolean shouldRestrict() {
        return sLevel.get() >= RiskResponsePolicy.Action.RESTRICT.ordinal();
    }
}
