#ifndef ENKO_ANTI_DEBUG_H
#define ENKO_ANTI_DEBUG_H

/** Start the anti-debug watchdog (ptrace self + background monitoring thread). */
void enko_anti_debug_start(void);

/**
 * Set the anti-debug enforcement policy.
 * @param block_mode  1 = kill process on detection (default), 0 = log only
 * Must be called after config is decrypted to honor risk-policy=log.
 */
void enko_anti_debug_set_policy(int block_mode);

/**
 * Native-layer risk detection.
 * Returns a bitmask:
 *   bit 0: debugger/tracer detected
 *   bit 1: frida detected in /proc/self/maps
 *   bit 2: timing anomaly (single-step suspected)
 *   bit 3: inline hook/text tamper detected on agpcore or tracked native code
 *   bit 4: root environment detected
 *   bit 5: emulator environment detected
 *   bit 6: hook framework traces detected in process maps
 *   bit 7: anti-dump strong signal detected
 *   bit 8: system integrity anomaly detected
 */
int enko_native_detect_risk(void);

/**
 * Native risk scoring + block decision.
 *
 * @param risk_profile  "strict" / "balanced" / "compat"
 * @param block_policy  1 if policy is block, 0 if log
 * @param reasons_csv   comma-separated risk reasons
 * @param out_score     output total score
 * @param out_signal_count output unique signal count
 * @param out_high_count output high-confidence signal count
 * @param out_should_block output 1=block, 0=log
 * @return 0 on success, -1 on invalid args
 */
int enko_native_evaluate_risk(
        const char *risk_profile,
        int block_policy,
        const char *reasons_csv,
        int *out_score,
        int *out_signal_count,
        int *out_high_count,
        int *out_should_block);

#endif
