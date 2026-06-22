"""Offline checks for the RHEL deployment scripts.

These don't run the script (no Linux/root needed); they assert that the files
agree with each other and with the project layout, so future refactors don't
silently break the deploy path.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"


def test_setup_rhel_script_exists_and_bash_parses() -> None:
    script = DEPLOY / "setup-rhel.sh"
    assert script.exists()
    # bash -n parses without executing
    result = subprocess.run(
        ["bash", "-n", str(script)],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, f"setup-rhel.sh has bash syntax error: {result.stderr}"


def test_setup_rhel_uses_dnf_not_apt() -> None:
    """Sanity: the RHEL script must not call apt/apt-get."""
    text = (DEPLOY / "setup-rhel.sh").read_text(encoding="utf-8")
    assert "apt-get" not in text
    assert "apt " not in text
    assert "dnf install" in text


def test_setup_rhel_writes_to_conf_d_not_sites_available() -> None:
    """RHEL nginx uses /etc/nginx/conf.d/, not Debian's sites-available."""
    text = (DEPLOY / "setup-rhel.sh").read_text(encoding="utf-8")
    assert "/etc/nginx/conf.d/enko.conf" in text
    assert "sites-available" not in text
    assert "sites-enabled" not in text


def test_systemd_unit_uses_app_dir() -> None:
    """web-console has a hyphen so it's not importable as a Python package
    without --app-dir. Make sure the unit uses that workaround."""
    unit = (DEPLOY / "enko-web.service").read_text(encoding="utf-8")
    assert "--app-dir" in unit
    assert "server_prod:app" in unit
    # The broken form (module path with hyphen) must NOT appear.
    assert "web-console.server_prod" not in unit


def test_nginx_template_exists_and_has_placeholders() -> None:
    tpl = DEPLOY / "nginx-enko-rhel.conf"
    assert tpl.exists()
    text = tpl.read_text(encoding="utf-8")
    assert "@SERVER_NAME@" in text
    assert "@ENKO_INSTALL_DIR@" in text
    # All Nginx critical blocks present.
    for needed in ("upstream enko_backend", "/api/", "client_max_body_size",
                   "proxy_set_header Upgrade", "try_files"):
        assert needed in text, f"nginx template missing: {needed}"


def test_setup_rhel_references_existing_files() -> None:
    """setup-rhel.sh references nginx template and systemd unit. Both must exist."""
    text = (DEPLOY / "setup-rhel.sh").read_text(encoding="utf-8")
    # extract the relative paths it copies
    nginx_ref = re.search(r"deploy/(nginx-enko-rhel\.conf)", text)
    systemd_ref = re.search(r"deploy/(enko-web\.service)", text)
    assert nginx_ref, "setup-rhel.sh must reference deploy/nginx-enko-rhel.conf"
    assert systemd_ref, "setup-rhel.sh must reference deploy/enko-web.service"
    assert (DEPLOY / nginx_ref.group(1)).exists()
    assert (DEPLOY / systemd_ref.group(1)).exists()


def test_setup_rhel_never_hardcodes_admin_password() -> None:
    """Regression for 1.1: the script must not ship a fixed admin password.
    It should generate one and persist to /etc/enko/.admin_password."""
    text = (DEPLOY / "setup-rhel.sh").read_text(encoding="utf-8")
    # No hardcoded credentials like enko2024 / admin123 / Enko@2024Secure.
    forbidden = ("enko2024", "admin123", "Enko@2024Secure", "password123")
    for word in forbidden:
        assert word not in text, f"hardcoded credential leaked: {word}"
    # Must use openssl rand for both JWT and admin password.
    assert "openssl rand -hex" in text
    assert ".admin_password" in text


def test_deploy_md_documents_setup_rhel() -> None:
    """The user-facing guide must mention the new RHEL script."""
    doc = ROOT / "docs" / "DEPLOY.md"
    assert doc.exists()
    text = doc.read_text(encoding="utf-8")
    assert "setup-rhel.sh" in text
    # Must call out the random admin password mechanism so operators know where to find it.
    assert ".admin_password" in text
