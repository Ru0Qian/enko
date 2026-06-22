from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace


REPO_ROOT = Path(__file__).resolve().parents[1]
PACKER_ROOT = REPO_ROOT / "packer"
if str(PACKER_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKER_ROOT))


def test_release_manifest_builds_relative_paths_by_default(tmp_path: Path) -> None:
    import release_manifest_tool

    release_dir = tmp_path / "release"
    release_dir.mkdir()
    engine = release_dir / "engine.json"
    rules = release_dir / "rules.json"
    policy = release_dir / "policy.json"
    presets = release_dir / "presets.json"
    protect = tmp_path / "protect.txt"
    output = release_dir / "release_manifest.json"

    engine.write_text('{"engine_version":"1.0.0","config_schema_version":"1"}', encoding="utf-8")
    rules.write_text('{"rules_version":"2026.05.05"}', encoding="utf-8")
    policy.write_text('{"policy_version":"2026.05.05"}', encoding="utf-8")
    presets.write_text('{"preset_version":"2026.05.05"}', encoding="utf-8")
    protect.write_text("Lcom/example/Test;->a()V 1\n", encoding="utf-8")

    args = SimpleNamespace(
        engine_manifest=str(engine),
        rules_file=str(rules),
        policy_file=str(policy),
        protection_map=str(protect),
        map_version="demo.v1",
        presets_file=str(presets),
        preset_version="",
        output=str(output),
        absolute_paths=False,
    )

    assert release_manifest_tool.build_manifest(args) == 0
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert payload["files"]["engine_manifest"]["path"] == "engine.json"
    assert payload["files"]["protection_map"]["path"] == "../protect.txt"
    assert not Path(payload["files"]["rules"]["path"]).is_absolute()

    validate_args = SimpleNamespace(manifest=str(output), check_files=True)
    assert release_manifest_tool.validate_manifest(validate_args) == 0


def test_current_release_manifest_uses_portable_paths() -> None:
    payload = json.loads((REPO_ROOT / "release" / "release_manifest.json").read_text(encoding="utf-8"))

    for meta in payload["files"].values():
        assert not Path(str(meta["path"])).is_absolute()
