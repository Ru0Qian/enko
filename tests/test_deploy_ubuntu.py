"""Offline checks for the Ubuntu deployment script (deploy/setup.sh).

Mirrors test_deploy_rhel.py — same security invariants must hold on both
distros. No Linux/root needed; pure static-file checks.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"


def test_setup_ubuntu_exists_and_bash_parses() -> None:
    script = DEPLOY / "setup.sh"
    assert script.exists()
    result = subprocess.run(
        ["bash", "-n", str(script)],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, f"setup.sh bash syntax error: {result.stderr}"


def test_setup_ubuntu_uses_apt_not_dnf() -> None:
    text = (DEPLOY / "setup.sh").read_text(encoding="utf-8")
    assert "apt-get install" in text
    assert "dnf install" not in text


def test_setup_ubuntu_writes_to_sites_available() -> None:
    """Debian/Ubuntu nginx uses sites-available + sites-enabled symlink."""
    text = (DEPLOY / "setup.sh").read_text(encoding="utf-8")
    assert "/etc/nginx/sites-available/enko" in text
    assert "/etc/nginx/sites-enabled/enko" in text


def test_setup_ubuntu_never_hardcodes_admin_password() -> None:
    """Regression: must never ship a fixed admin password."""
    text = (DEPLOY / "setup.sh").read_text(encoding="utf-8")
    forbidden = ("enko2024", "admin123", "Enko@2024Secure", "password123")
    for word in forbidden:
        assert word not in text, f"hardcoded credential leaked in setup.sh: {word}"
    # Must generate JWT and admin password with openssl rand.
    assert "openssl rand -hex" in text
    assert ".admin_password" in text


def test_setup_ubuntu_uses_shared_systemd_unit() -> None:
    """Both Ubuntu and RHEL scripts must install the same fixed systemd unit
    (which uses --app-dir so the hyphenated 'web-console' module imports
    correctly)."""
    text = (DEPLOY / "setup.sh").read_text(encoding="utf-8")
    assert "deploy/enko-web.service" in text or "/enko-web.service" in text
    unit = (DEPLOY / "enko-web.service").read_text(encoding="utf-8")
    assert "--app-dir" in unit
    assert "server_prod:app" in unit
    assert "web-console.server_prod" not in unit


def test_setup_ubuntu_creates_etc_enko_dir_secure() -> None:
    text = (DEPLOY / "setup.sh").read_text(encoding="utf-8")
    # /etc/enko should be 700 (only root reads), .admin_password 600.
    assert re.search(r"mkdir -p /etc/enko", text)
    assert "chmod 600" in text or "chmod 700" in text


def test_ubuntu_deploy_md_exists_and_mentions_setup_sh() -> None:
    doc = ROOT / "docs" / "DEPLOY-UBUNTU.md"
    assert doc.exists()
    text = doc.read_text(encoding="utf-8")
    # Operator must know the script path and the admin-password file.
    assert "deploy/setup.sh" in text
    assert ".admin_password" in text
    # Common-task commands and troubleshooting present.
    assert "systemctl" in text
    assert "journalctl" in text
