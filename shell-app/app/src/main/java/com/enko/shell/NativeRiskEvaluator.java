package com.enko.shell;

import java.util.List;

final class NativeRiskEvaluator {

    static final class Decision {
        final int score;
        final int signalCount;
        final int highConfidenceCount;
        final boolean shouldBlock;

        Decision(int score, int signalCount, int highConfidenceCount, boolean shouldBlock) {
            this.score = score;
            this.signalCount = signalCount;
            this.highConfidenceCount = highConfidenceCount;
            this.shouldBlock = shouldBlock;
        }
    }

    private NativeRiskEvaluator() {
    }

    static Decision evaluate(RuntimeConfig cfg, List<String> reasons) {
        if (reasons == null || reasons.isEmpty()) {
            return new Decision(0, 0, 0, false);
        }

        boolean blockPolicy = cfg != null && cfg.shouldBlockOnRisk();
        String profile = cfg != null ? cfg.riskProfile : RuntimeConfig.PROFILE_BALANCED;

        if (!NativeBridge.isAvailable()) {
            throw new SecurityException("native risk evaluator unavailable");
        }

        try {
            int[] out = NativeBridge.nativeEvaluateRisk(profile, blockPolicy, joinReasons(reasons));
            if (out != null && out.length >= 4) {
                return new Decision(out[0], out[1], out[2], out[3] != 0);
            }
            throw new SecurityException("native risk evaluator returned invalid output");
        } catch (SecurityException e) {
            throw e;
        } catch (Throwable t) {
            throw new SecurityException("native risk evaluator failed", t);
        }
    }

    static String joinReasons(List<String> reasons) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < reasons.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(reasons.get(i));
        }
        return sb.toString();
    }
}
