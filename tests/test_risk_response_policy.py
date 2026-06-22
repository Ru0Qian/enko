"""Tests for the P6-1 graded risk response policy (RiskResponsePolicy).

Two layers:
  1. Source-inspection checks (always run, no JDK needed) — match the project's
     existing shell-Java test convention (see test_shell_vmp_targets.py).
  2. A javac compile-and-run behavioral check of the pure-Java decision matrix,
     skipped when no JDK is available so the Python-only CI suite stays green.

The core commercial guarantee under test: process termination is only reachable
under the strict profile or commercial mode; balanced/compat cap at RESTRICT.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SHELL_JAVA = ROOT / "shell-app" / "app" / "src" / "main" / "java" / "com" / "enko" / "shell"
POLICY_SRC = SHELL_JAVA / "RiskResponsePolicy.java"
STATE_SRC = SHELL_JAVA / "RiskState.java"


def test_policy_and_state_sources_exist() -> None:
    assert POLICY_SRC.exists(), "RiskResponsePolicy.java missing"
    assert STATE_SRC.exists(), "RiskState.java missing"


def test_policy_defines_five_graded_actions() -> None:
    src = POLICY_SRC.read_text(encoding="utf-8")
    for action in ("ALLOW", "MONITOR", "CHALLENGE", "RESTRICT", "TERMINATE"):
        assert action in src, f"action {action} not defined in RiskResponsePolicy"


def test_termination_is_gated_on_strict_or_commercial() -> None:
    """The downgrade-from-TERMINATE guard must exist in source."""
    src = POLICY_SRC.read_text(encoding="utf-8")
    assert "allowsTermination" in src
    # The guarantee: only commercial mode or strict profile permits termination.
    assert "commercialMode" in src
    assert "PROFILE_STRICT" in src


_JAVA_HARNESS = r"""
package com.enko.shell;

public class RiskPolicyHarness {
    public static void main(String[] args) {
        String[] policies = {"off", "log", "warn", "degrade", "block"};
        String[] profiles = {"compat", "balanced", "strict"};
        boolean[] commercials = {false, true};
        // score, highConfidenceCount
        int[][] decisions = {
            {0, 0}, {45, 0}, {75, 0}, {95, 0}, {50, 1}, {50, 2},
        };
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        boolean first = true;
        for (String policy : policies) {
            for (String profile : profiles) {
                for (boolean commercial : commercials) {
                    RuntimeConfig cfg = new RuntimeConfig(policy, profile, commercial);
                    for (int[] d : decisions) {
                        int signals = (d[0] == 0 && d[1] == 0) ? 0 : 1;
                        NativeRiskEvaluator.Decision dec =
                            new NativeRiskEvaluator.Decision(d[0], signals, d[1], d[0] >= 70);
                        RiskResponsePolicy.Action a = RiskResponsePolicy.decide(cfg, dec);
                        if (!first) sb.append(",");
                        first = false;
                        sb.append("{\"policy\":\"").append(policy)
                          .append("\",\"profile\":\"").append(profile)
                          .append("\",\"commercial\":").append(commercial)
                          .append(",\"score\":").append(d[0])
                          .append(",\"high\":").append(d[1])
                          .append(",\"action\":\"").append(a.name()).append("\"}");
                    }
                }
            }
        }
        sb.append("]");
        System.out.println(sb.toString());
    }
}
"""

_RUNTIMECONFIG_STUB = """
package com.enko.shell;
final class RuntimeConfig {
    static final String POLICY_BLOCK="block",POLICY_DEGRADE="degrade",POLICY_WARN="warn",POLICY_LOG="log",POLICY_OFF="off";
    static final String PROFILE_STRICT="strict",PROFILE_BALANCED="balanced",PROFILE_COMPAT="compat";
    final String riskPolicy, riskProfile; final boolean commercialMode;
    RuntimeConfig(String p,String pr,boolean c){riskPolicy=p;riskProfile=pr;commercialMode=c;}
    boolean isOffPolicy(){return POLICY_OFF.equals(riskPolicy);}
}
"""

_EVALUATOR_STUB = """
package com.enko.shell;
final class NativeRiskEvaluator {
    static final class Decision {
        final int score,signalCount,highConfidenceCount; final boolean shouldBlock;
        Decision(int s,int sc,int h,boolean b){score=s;signalCount=sc;highConfidenceCount=h;shouldBlock=b;}
    }
}
"""


def _run_decision_matrix(tmp_path: Path) -> list[dict]:
    pkg = tmp_path / "com" / "enko" / "shell"
    pkg.mkdir(parents=True)
    (pkg / "RiskResponsePolicy.java").write_text(
        POLICY_SRC.read_text(encoding="utf-8"), encoding="utf-8")
    (pkg / "RiskState.java").write_text(
        STATE_SRC.read_text(encoding="utf-8"), encoding="utf-8")
    (pkg / "RuntimeConfig.java").write_text(_RUNTIMECONFIG_STUB, encoding="utf-8")
    (pkg / "NativeRiskEvaluator.java").write_text(_EVALUATOR_STUB, encoding="utf-8")
    (pkg / "RiskPolicyHarness.java").write_text(_JAVA_HARNESS, encoding="utf-8")

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    sources = [str(p) for p in pkg.glob("*.java")]
    subprocess.run(
        ["javac", "-encoding", "UTF-8", "-d", str(out_dir), *sources],
        check=True, capture_output=True, text=True,
    )
    result = subprocess.run(
        ["java", "-cp", str(out_dir), "com.enko.shell.RiskPolicyHarness"],
        check=True, capture_output=True, text=True,
    )
    return json.loads(result.stdout.strip())


@pytest.mark.skipif(
    not (shutil.which("javac") and shutil.which("java")),
    reason="JDK (javac/java) not available; behavioral matrix test skipped",
)
def test_graded_matrix_behavior(tmp_path: Path) -> None:
    rows = _run_decision_matrix(tmp_path)
    assert rows, "harness produced no rows"

    for row in rows:
        action = row["action"]
        # Core guarantee: balanced/compat (non-commercial) must NEVER terminate.
        if row["profile"] in ("balanced", "compat") and not row["commercial"]:
            assert action != "TERMINATE", f"non-strict build terminated: {row}"

        # off policy => always ALLOW.
        if row["policy"] == "off":
            assert action == "ALLOW", f"off policy did not allow: {row}"

        # log policy => never escalate beyond MONITOR.
        if row["policy"] == "log" and row["score"] > 0:
            assert action in ("ALLOW", "MONITOR"), f"log policy escalated: {row}"

        # No risk signal => ALLOW regardless of policy.
        if row["score"] == 0 and row["high"] == 0:
            assert action == "ALLOW", f"no-signal not allowed: {row}"

    # Termination must be reachable for a strict+block critical case.
    strict_block_critical = [
        r for r in rows
        if r["policy"] == "block" and r["profile"] == "strict" and r["high"] >= 2
    ]
    assert any(r["action"] == "TERMINATE" for r in strict_block_critical), \
        "strict+block critical risk never terminates"

    # And a balanced+block critical case must cap at RESTRICT, not kill.
    balanced_block_critical = [
        r for r in rows
        if r["policy"] == "block" and r["profile"] == "balanced"
        and not r["commercial"] and r["high"] >= 2
    ]
    assert balanced_block_critical
    assert all(r["action"] == "RESTRICT" for r in balanced_block_critical), \
        "balanced+block critical risk should cap at RESTRICT"
