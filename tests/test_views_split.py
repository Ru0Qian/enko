"""Stage 2 view-split regression tests.

After splitting <section id="view-X"> blocks out of index.html into views/*.html,
the dev server still has to serve everything, and the combined DOM (shell +
all views) must still expose every id that app.js calls
``document.getElementById`` on. These tests are offline (no server needed) and
just walk the static files.
"""
from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "web-console"
VIEWS = WEB / "views"


VIEW_NAMES = [
    "dashboard", "new-job", "jobs", "job-detail",
    "reports", "profiles", "admin",
]

# IDs that app.js / jobs.js / analyzer.js / report.js call
# document.getElementById on. Discovered by grep at the time of writing; the
# test acts as a regression contract — if a future refactor renames any of
# these without updating the views, this test catches it.
CRITICAL_IDS = {
    # core form
    "inputApk", "shellApk", "outputApk", "ndkPath", "protectionMap",
    "reportJsonPath", "releaseManifestPath", "minExtract", "minVmp",
    "minDex2c", "minScore",
    # protection feature checkboxes
    "featureExtract", "featureVmpDex", "featureDex2c",
    "featureVmpShellDex", "featurePolymorphicShell", "featureAiDecoy",
    "extractOnDemand", "methodSmartPreset", "vmpObfuscationPreset",
    "vmpVmTier", "dex2cOllvm", "dex2cOllvmRequired", "dex2cOllvmClang",
    # risk + signing
    "commercialMode", "flutterMode", "signingEnabled", "signCertSha256",
    "perApkKey", "detectRoot", "detectEmulator", "protectDexPages",
    "blockProxyVpn", "releaseManifestEnabled",
    # action bar + command preview
    "commandPreview", "copyCommand", "startHardening",
    "signingBox", "externalSigningBox",
    # job detail / log
    "jobLog", "jobStatusBadge", "jobOutputApk", "jobReportPath",
    "jobReportSummaryList", "jobMetaList", "jobCommandPreview",
    "jobIdValue", "jobReturnCode", "jobDuration",
    # report view
    "reportFile", "loadSample", "controlsList", "recommendationsList",
    "nativeCoreList",
    # method analyzer
    "methodTableBody", "methodAdvancedBody", "apkDropZone", "apkFileInput",
    # chrome
    "toast-container", "sidebar", "topbar-title", "topbar-username",
}


def test_index_html_shrunk_below_300_lines() -> None:
    """Sanity: split should have removed >1400 lines from index.html."""
    text = (WEB / "index.html").read_text(encoding="utf-8")
    line_count = text.count("\n")
    assert line_count < 300, f"index.html should be small after split (was {line_count})"


def test_views_directory_has_seven_files() -> None:
    actual = sorted(p.name for p in VIEWS.iterdir() if p.suffix == ".html")
    expected = sorted(f"{name}.html" for name in VIEW_NAMES)
    assert actual == expected, f"views/ mismatch: {actual} vs {expected}"


def test_index_has_view_host_placeholder() -> None:
    text = (WEB / "index.html").read_text(encoding="utf-8")
    assert 'id="view-host"' in text, "index.html must declare #view-host for views.js"


def test_index_loads_views_js_before_app_js() -> None:
    """views.js must be loaded before app.js so the bootstrap event lands."""
    text = (WEB / "index.html").read_text(encoding="utf-8")
    views_pos = text.find('src="js/views.js')
    app_pos = text.find('src="app.js')
    assert views_pos > 0, "views.js not loaded"
    assert app_pos > 0, "app.js not loaded"
    assert views_pos < app_pos, "views.js must precede app.js in the DOM"


def test_no_view_sections_left_in_index() -> None:
    """All <section id='view-X'> blocks must have moved to views/*.html.
    (id="view-host" is the injection target and is allowed.)"""
    text = (WEB / "index.html").read_text(encoding="utf-8")
    # Find every id starting with "view-" and confirm none of them are view-*
    # other than the host placeholder.
    leaked = [m.group(1) for m in re.finditer(r'id="(view-[^"]+)"', text)
              if m.group(1) != "view-host"]
    assert not leaked, f"index.html still contains view sections: {leaked}"


def test_every_view_file_has_top_level_section() -> None:
    """Each views/<name>.html must start with the matching <section id='view-name'>."""
    for name in VIEW_NAMES:
        path = VIEWS / f"{name}.html"
        text = path.read_text(encoding="utf-8")
        assert text.lstrip().startswith(f'<section id="view-{name}"'), \
            f"{path.name} does not open with the expected section tag"


def test_combined_dom_exposes_every_critical_id() -> None:
    """The shell (index.html) + all views combined must contain every id
    that the JS modules query via document.getElementById."""
    combined = (WEB / "index.html").read_text(encoding="utf-8")
    for name in VIEW_NAMES:
        combined += (VIEWS / f"{name}.html").read_text(encoding="utf-8")
    missing = [i for i in CRITICAL_IDS if f'id="{i}"' not in combined]
    assert not missing, f"missing critical ids after view split: {missing}"


def test_app_js_init_deferred_until_views_ready() -> None:
    """app.js bottom must wait for the enko-views-ready event."""
    text = (WEB / "app.js").read_text(encoding="utf-8")
    # No bare init() at end — must be guarded.
    assert "window.enkoInit" in text, "app.js must expose enkoInit for views.js"
    assert "enko-views-ready" in text, "app.js must listen for enko-views-ready"


def test_views_js_fetches_all_seven_views() -> None:
    text = (WEB / "js" / "views.js").read_text(encoding="utf-8")
    for name in VIEW_NAMES:
        # Either listed in VIEW_NAMES array or referenced explicitly.
        assert f'"{name}"' in text or f"'{name}'" in text, \
            f"views.js does not load views/{name}.html"
