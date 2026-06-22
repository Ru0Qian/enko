from __future__ import annotations

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
WEB_ROOT = REPO_ROOT / "web-console"
if str(WEB_ROOT) not in sys.path:
    sys.path.insert(0, str(WEB_ROOT))


def _base_config(tmp_path: Path) -> dict[str, object]:
    return {
        "inputApk": str(tmp_path / "input.apk"),
        "shellApk": str(tmp_path / "shell.apk"),
        "outputApk": str(tmp_path / "out.apk"),
        "riskPolicy": "log",
        "riskProfile": "compat",
        "featureExtract": True,
        "featureVmpDex": False,
        "featureDex2c": False,
        "signingEnabled": False,
    }


def _patch_tool_defaults(monkeypatch, tmp_path: Path) -> None:
    import common

    zipalign = tmp_path / "zipalign"
    apksigner = tmp_path / "apksigner"
    zipalign.write_text("", encoding="utf-8")
    apksigner.write_text("", encoding="utf-8")
    monkeypatch.setattr(
        common,
        "discover_environment_defaults",
        lambda: {
            "apktool": "",
            "zipalign": str(zipalign),
            "apksigner": str(apksigner),
            "ndk": "",
        },
    )


def test_web_command_defaults_to_unsigned_external_signing(monkeypatch, tmp_path: Path) -> None:
    import common

    _patch_tool_defaults(monkeypatch, tmp_path)
    args, _preview, _metadata = common.build_command(_base_config(tmp_path), tmp_path)

    assert "--skip-sign" in args
    assert "--sign" not in args
    assert "--keystore" not in args


def test_web_command_adds_explicit_sign_flag_for_in_pipeline_signing(monkeypatch, tmp_path: Path) -> None:
    import common

    _patch_tool_defaults(monkeypatch, tmp_path)
    config = _base_config(tmp_path)
    config.update(
        {
            "signingEnabled": True,
            "keystorePath": str(tmp_path / "release.jks"),
            "ksPass": "secret",
            "keyAlias": "release",
            "keyPass": "secret",
        }
    )

    args, _preview, _metadata = common.build_command(config, tmp_path)

    assert "--sign" in args
    assert "--skip-sign" not in args
    assert "--keystore" in args


def test_job_snapshot_persists_and_marks_stale_running_failed(monkeypatch, tmp_path: Path) -> None:
    import json
    import common

    monkeypatch.setattr(common, "JOB_ROOT", tmp_path)
    with common.JOBS_LOCK:
        common.JOBS.clear()

    job_id = "stale123"
    job_dir = tmp_path / job_id
    job_dir.mkdir()
    (job_dir / common.JOB_STATE_FILENAME).write_text(
        json.dumps(
            {
                "id": job_id,
                "status": "running",
                "created_at": "2026-05-05T00:00:00+08:00",
                "started_at": "2026-05-05T00:00:01+08:00",
                "finished_at": None,
                "returncode": None,
                "log": ["started"],
                "output_apk": "",
                "report_json": "",
            }
        ),
        encoding="utf-8",
    )

    assert common.load_persisted_jobs() == 1
    snapshot = common.snapshot_job(job_id)

    assert snapshot["status"] == "failed"
    assert snapshot["returncode"] == -1
    assert "服务重启" in snapshot["error"]
    assert any("interrupted" in line for line in snapshot["log"])


def test_snapshot_job_attaches_report_and_artifact_status(monkeypatch, tmp_path: Path) -> None:
    import json
    import common

    monkeypatch.setattr(common, "JOB_ROOT", tmp_path)
    with common.JOBS_LOCK:
        common.JOBS.clear()

    output_apk = tmp_path / "out.apk"
    report_json = tmp_path / "report.json"
    output_apk.write_bytes(b"apk")
    report_json.write_text(
        json.dumps(
            {
                "score": 96,
                "max_score": 100,
                "grade": "A",
                "compiled": {"extract": 1, "vmp_dex": 2, "dex2c": 3},
                "method_protection": {
                    "dex2c_native_obfuscation": {
                        "ollvm_effective": True,
                        "ollvm_protected_abis": ["arm64-v8a"],
                    },
                    "vmp_obfuscation": {
                        "string_pool_format_version": 4,
                        "effective_split_prob": 0.08,
                    },
                    "vmp_bytecode_format": {
                        "blob_version": 4,
                        "instruction_encoding": "fixed8",
                        "instruction_width_bytes": 8,
                        "field_layout_randomized": False,
                        "variable_length_supported": False,
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    with common.JOBS_LOCK:
        common.JOBS["done123"] = {
            "id": "done123",
            "status": "succeeded",
            "created_at": common.now_iso(),
            "started_at": common.now_iso(),
            "finished_at": common.now_iso(),
            "returncode": 0,
            "log": [],
            "output_apk": str(output_apk),
            "report_json": str(report_json),
        }

    snapshot = common.snapshot_job("done123")

    assert snapshot["output_exists"] is True
    assert snapshot["report_exists"] is True
    assert snapshot["report_score"] == 96
    assert snapshot["report_grade"] == "A"
    assert snapshot["report"]["method_protection"]["dex2c_native_obfuscation"]["ollvm_effective"] is True
    assert snapshot["report"]["method_protection"]["vmp_bytecode_format"]["instruction_encoding"] == "fixed8"


def test_web_ui_exposes_capability_matrix_for_supported_features() -> None:
    # After Stage 2 the new-job view was split out to views/new-job.html.
    # The browser DOM = index.html + every views/*.html, so check the union.
    index = (WEB_ROOT / "index.html").read_text(encoding="utf-8")
    views_dir = WEB_ROOT / "views"
    combined = index + "".join(
        p.read_text(encoding="utf-8") for p in sorted(views_dir.glob("*.html"))
    )
    app_js = (WEB_ROOT / "app.js").read_text(encoding="utf-8")

    assert 'id="capabilityMatrix"' in combined
    assert "function renderCapabilityMatrix" in app_js
    for label in [
        "方法抽取",
        "VMP DEX",
        "壳自保护",
        "DEX2C",
        "多态壳",
        "DEX 页封存",
        "签名策略",
        "发布门禁",
    ]:
        assert label in app_js


def test_web_frontend_splits_job_and_report_renderers() -> None:
    index = (WEB_ROOT / "index.html").read_text(encoding="utf-8")
    app_js = (WEB_ROOT / "app.js").read_text(encoding="utf-8")
    jobs_js = (WEB_ROOT / "js" / "jobs.js").read_text(encoding="utf-8")
    report_js = (WEB_ROOT / "js" / "report.js").read_text(encoding="utf-8")

    assert 'src="js/report.js' in index
    assert 'src="js/jobs.js' in index
    assert "function renderJob" not in app_js
    assert "function renderReport" not in app_js
    assert "function renderJob" in jobs_js
    assert "function loadJobsPage" in jobs_js
    assert "function renderReport" in report_js
    assert "function buildJobReportSummary" in report_js
    assert "VMP 指令格式" in report_js
    assert "vmp_bytecode_format" in report_js


def test_web_ui_exposes_compat_and_strong_quick_presets() -> None:
    index = (WEB_ROOT / "index.html").read_text(encoding="utf-8")
    views_dir = WEB_ROOT / "views"
    combined = index + "".join(
        p.read_text(encoding="utf-8") for p in sorted(views_dir.glob("*.html"))
    )
    app_js = (WEB_ROOT / "app.js").read_text(encoding="utf-8")

    assert 'data-quick-preset="compat"' in combined
    assert 'data-quick-preset="strong"' in combined
    assert "function applyQuickPreset" in app_js
    assert 'riskProfile: "compat"' in app_js
    assert 'vmpObfuscationPreset: "medium"' in app_js
    assert "dex2cOllvmRequired: true" in app_js


def test_web_upload_auto_runs_method_analysis_and_saves_map() -> None:
    app_js = (WEB_ROOT / "app.js").read_text(encoding="utf-8")
    analyzer_js = (WEB_ROOT / "js" / "analyzer.js").read_text(encoding="utf-8")

    assert 'runMethodAnalysis({ autoSaveRecommended: true, quiet: true })' in app_js
    assert "async function runMethodAnalysis(options = {})" in analyzer_js
    assert "await acceptRecommendedMap({ quiet: true })" in analyzer_js
    assert "async function acceptRecommendedMap(options = {})" in analyzer_js


# -- P5-7 AI decoy flag wiring -------------------------------------------

def test_ai_decoy_flag_emitted_when_toggled(tmp_path, monkeypatch) -> None:
    _patch_tool_defaults(monkeypatch, tmp_path)
    import common
    cfg = _base_config(tmp_path)
    cfg["featureAiDecoy"] = True
    cfg["commercialMode"] = False
    argv, _, _ = common.build_command(cfg, tmp_path)
    assert "--ai-decoy" in argv, "explicit AI decoy toggle should emit --ai-decoy"


def test_ai_decoy_flag_suppressed_under_commercial_mode(tmp_path, monkeypatch) -> None:
    """Commercial mode auto-enables in the packer; UI must not double-emit."""
    _patch_tool_defaults(monkeypatch, tmp_path)
    import common
    cfg = _base_config(tmp_path)
    cfg["featureAiDecoy"] = True
    cfg["commercialMode"] = True
    cfg["riskPolicy"] = "block"
    cfg["riskProfile"] = "strict"
    cfg["blockProxyVpn"] = True
    cfg["perApkKey"] = True
    cfg["signingEnabled"] = False
    argv, _, _ = common.build_command(cfg, tmp_path)
    assert "--ai-decoy" not in argv, "commercial mode auto-enables; flag must not double up"


def test_ai_decoy_default_off(tmp_path, monkeypatch) -> None:
    _patch_tool_defaults(monkeypatch, tmp_path)
    import common
    cfg = _base_config(tmp_path)
    argv, _, _ = common.build_command(cfg, tmp_path)
    assert "--ai-decoy" not in argv, "default is off; no flag expected"
