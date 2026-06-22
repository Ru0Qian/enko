from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"


def test_ci_workflow_covers_release_hygiene_and_scenario_builds() -> None:
    text = CI_WORKFLOW.read_text(encoding="utf-8")

    assert "hygiene-and-release:" in text
    assert "python tools/check_repo_hygiene.py" in text
    assert "python packer/release_manifest_tool.py validate --manifest release/release_manifest.json --check-files" in text
    assert "scenario-apk-build:" in text
    assert "android-actions/setup-android@v3" in text
    assert "shell-app/gradlew -p test_apks/scenario_app assembleDebug --no-daemon" in text
    assert "python tools/run_scenario_matrix.py --skip-build --skip-harden --smoke never" in text
    assert '--gradle "$GITHUB_WORKSPACE/shell-app/gradlew"' in text


def test_ci_workflow_has_manual_device_smoke_gate() -> None:
    text = CI_WORKFLOW.read_text(encoding="utf-8")

    assert "workflow_dispatch:" in text
    assert "run_device_smoke:" in text
    assert "device_smoke_scenario:" in text
    assert "device-smoke:" in text
    assert "github.event_name == 'workflow_dispatch' && inputs.run_device_smoke == 'true'" in text
    assert "runs-on: [self-hosted, android]" in text
    assert "--skip-harden --smoke always --smoke-raw" in text
