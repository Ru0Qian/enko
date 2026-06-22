from __future__ import annotations

import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS_ROOT = REPO_ROOT / "tools"
if str(TOOLS_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLS_ROOT))


def test_clean_workspace_default_does_not_select_output(monkeypatch, tmp_path: Path) -> None:
    import clean_workspace

    monkeypatch.setattr(clean_workspace, "ROOT", tmp_path)
    monkeypatch.setattr(clean_workspace, "TOOLCHAIN_DIRS", set())

    (tmp_path / ".pytest_cache").mkdir()
    output = tmp_path / "output"
    output.mkdir()
    (output / "old.apk").write_bytes(b"apk")

    default_entries = clean_workspace.collect(clean_workspace.DEFAULT_CATEGORIES)
    output_entries = clean_workspace.collect(["output"])

    assert all(entry.category != "output" for entry in default_entries)
    assert [entry.path.name for entry in output_entries] == ["old.apk"]


def test_clean_workspace_json_plan(monkeypatch, tmp_path: Path, capsys) -> None:
    import clean_workspace

    monkeypatch.setattr(clean_workspace, "ROOT", tmp_path)
    monkeypatch.setattr(clean_workspace, "TOOLCHAIN_DIRS", set())
    monkeypatch.setattr(sys, "argv", ["clean_workspace.py", "--category", "cache", "--json"])

    cache_dir = tmp_path / ".pytest_cache"
    cache_dir.mkdir()

    assert clean_workspace.main() == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["mode"] == "dry-run"
    assert payload["categories"] == ["cache"]
    assert payload["entry_count"] == 1
    assert payload["entries"][0]["path"] == ".pytest_cache"
