"""Tests for polymorphic shell package generation."""

import sys
from pathlib import Path

_packer = Path(__file__).resolve().parent.parent / "packer"
if str(_packer) not in sys.path:
    sys.path.insert(0, str(_packer))

from harden_apk import (
    SHELL_PKG_SLASH,
    SHELL_POLY_FIELD_NAMES,
    generate_polymorphic_package,
    generate_shell_symbol_aliases,
)


def test_generated_package_stays_in_dex_sort_neighborhood():
    """Generated package strings must not move past neighboring DEX strings."""
    for _ in range(200):
        pkg = generate_polymorphic_package()
        dot = pkg.replace("/", ".")

        assert len(pkg) == len(SHELL_PKG_SLASH)
        assert pkg.startswith("com/en")
        assert "com.emanuelef.remote_capture.debug" < dot < "com.guoshi.httpcanary"


def test_shell_symbol_aliases_include_field_names():
    class_aliases, method_aliases, field_aliases = generate_shell_symbol_aliases()

    assert field_aliases
    # Names long enough to support prefix_len(5) + rank_token(2) + tail(>=1)
    # are always aliased. Shorter ones (e.g. "buildId" at 7 chars) are
    # intentionally left unaliased to preserve DEX string_ids ordering.
    long_field_names = [n for n in SHELL_POLY_FIELD_NAMES if len(n) >= 8]
    assert set(long_field_names).issubset(field_aliases)
    assert "runtimeConfig" in field_aliases
    assert "expectedSignSha256" in field_aliases
    assert len(class_aliases["ProxyApplication"]) == len("ProxyApplication")
    assert len(method_aliases["installPayload"]) == len("installPayload")
    assert len(field_aliases["runtimeConfig"]) == len("runtimeConfig")
    assert field_aliases["runtimeConfig"] != "runtimeConfig"
