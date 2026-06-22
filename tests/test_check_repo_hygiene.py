from __future__ import annotations

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS_ROOT = REPO_ROOT / "tools"
if str(TOOLS_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLS_ROOT))


def test_repo_hygiene_required_gitignore_patterns_present() -> None:
    import check_repo_hygiene

    report = check_repo_hygiene.build_report(REPO_ROOT)

    assert report["missing_gitignore_patterns"] == []


def test_repo_hygiene_detects_missing_patterns(tmp_path: Path) -> None:
    import check_repo_hygiene

    (tmp_path / ".gitignore").write_text("*.apk\n", encoding="utf-8")

    missing = check_repo_hygiene.missing_gitignore_patterns(tmp_path)

    assert "*.jks" in missing
    assert "tools/apktool_3.0.1.jar" in missing


def test_repo_hygiene_matches_forbidden_tracked_files() -> None:
    import check_repo_hygiene

    assert check_repo_hygiene.is_forbidden_tracked("output/demo.apk")
    assert check_repo_hygiene.is_forbidden_tracked("release.jks")
    assert check_repo_hygiene.is_forbidden_tracked("tools/gradle-8.2.1-bin.zip")
    assert not check_repo_hygiene.is_forbidden_tracked("packer/harden_apk.py")


def test_repo_hygiene_guards_env_secrets() -> None:
    import check_repo_hygiene

    # *.env and deploy/config.env must be required ignore patterns so real
    # secrets never get committed.
    assert "*.env" in check_repo_hygiene.REQUIRED_GITIGNORE_PATTERNS
    assert "deploy/config.env" in check_repo_hygiene.REQUIRED_GITIGNORE_PATTERNS
    # The secret-bearing config.env must be flagged if tracked; the committed
    # placeholder example must not be.
    assert check_repo_hygiene.is_forbidden_tracked("deploy/config.env")
    assert not check_repo_hygiene.is_forbidden_tracked("deploy/config.env.example")

