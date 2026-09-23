"""v5.0 Module interface contract tests.

Each of the 5 core modules must expose three interfaces:
- available() -> bool
- self_check() -> tuple[bool, str]
- module_version() -> str
"""

from __future__ import annotations

import re
import unittest

import fp_sentinel.attack.dom_verify as dom_verify_mod
import fp_sentinel.attack.harmless_verifier as harmless_mod
import fp_sentinel.api_knowledge as api_knowledge_mod
import fp_sentinel.api_knowledge.store as store_mod
import fp_sentinel.api_knowledge.associator as associator_mod
import fp_sentinel.web_api as web_api_mod

SEMVER_RE = re.compile(r"\d+\.\d+\.\d+")


# ─── available() returns bool ───────────────────────────────────────────────


def test_available_dom_verify() -> None:
    """Assert dom_verify.available() returns a bool."""
    assert isinstance(dom_verify_mod.available(), bool)


def test_available_store() -> None:
    """Assert store.available() returns a bool."""
    assert isinstance(store_mod.available(), bool)


def test_available_associator() -> None:
    """Assert associator.available() returns a bool."""
    assert isinstance(associator_mod.available(), bool)


def test_available_api_discovery() -> None:
    """Assert web_api.available() returns a bool."""
    assert isinstance(web_api_mod.available(), bool)


def test_available_harmless_verifier() -> None:
    """Assert harmless_verifier.available() returns a bool."""
    assert isinstance(harmless_mod.available(), bool)


# ─── self_check() returns tuple ─────────────────────────────────────────────


def test_self_check_dom_verify() -> None:
    """Assert dom_verify.self_check() returns a (bool, str) tuple."""
    result = dom_verify_mod.self_check()
    assert isinstance(result, tuple)
    assert len(result) == 2
    ok, msg = result
    assert isinstance(ok, bool)
    assert isinstance(msg, str)


def test_self_check_store() -> None:
    """Assert store.self_check() returns a (bool, str) tuple."""
    result = store_mod.self_check()
    assert isinstance(result, tuple)
    assert len(result) == 2
    ok, msg = result
    assert isinstance(ok, bool)
    assert isinstance(msg, str)


def test_self_check_associator() -> None:
    """Assert associator.self_check() returns a (bool, str) tuple."""
    result = associator_mod.self_check()
    assert isinstance(result, tuple)
    assert len(result) == 2
    ok, msg = result
    assert isinstance(ok, bool)
    assert isinstance(msg, str)


def test_self_check_api_discovery() -> None:
    """Assert web_api.self_check() returns a (bool, str) tuple."""
    result = web_api_mod.self_check()
    assert isinstance(result, tuple)
    assert len(result) == 2
    ok, msg = result
    assert isinstance(ok, bool)
    assert isinstance(msg, str)


def test_self_check_harmless_verifier() -> None:
    """Assert harmless_verifier.self_check() returns a (bool, str) tuple."""
    result = harmless_mod.self_check()
    assert isinstance(result, tuple)
    assert len(result) == 2
    ok, msg = result
    assert isinstance(ok, bool)
    assert isinstance(msg, str)


# ─── module_version() is semver ─────────────────────────────────────────────


def test_version_dom_verify() -> None:
    """Assert dom_verify.module_version() matches semver pattern."""
    version = dom_verify_mod.module_version()
    assert isinstance(version, str)
    assert SEMVER_RE.search(version), f"not semver: {version}"


def test_version_store() -> None:
    """Assert store.module_version() matches semver pattern."""
    version = store_mod.module_version()
    assert isinstance(version, str)
    assert SEMVER_RE.search(version), f"not semver: {version}"


def test_version_associator() -> None:
    """Assert associator.module_version() matches semver pattern."""
    version = associator_mod.module_version()
    assert isinstance(version, str)
    assert SEMVER_RE.search(version), f"not semver: {version}"


def test_version_api_discovery() -> None:
    """Assert web_api.module_version() matches semver pattern."""
    version = web_api_mod.module_version()
    assert isinstance(version, str)
    assert SEMVER_RE.search(version), f"not semver: {version}"


def test_version_harmless_verifier() -> None:
    """Assert harmless_verifier.module_version() matches semver pattern."""
    version = harmless_mod.module_version()
    assert isinstance(version, str)
    assert SEMVER_RE.search(version), f"not semver: {version}"


# ─── All exports present ────────────────────────────────────────────────────


def test_all_exports_present() -> None:
    """Assert all 5 packages expose the complete interface contract."""
    modules_and_funcs = [
        (dom_verify_mod, "dom_verify", "available"),
        (dom_verify_mod, "dom_verify", "self_check"),
        (dom_verify_mod, "dom_verify", "module_version"),
        (store_mod, "store", "available"),
        (store_mod, "store", "self_check"),
        (store_mod, "store", "module_version"),
        (associator_mod, "associator", "available"),
        (associator_mod, "associator", "self_check"),
        (associator_mod, "associator", "module_version"),
        (web_api_mod, "web_api", "available"),
        (web_api_mod, "web_api", "self_check"),
        (web_api_mod, "web_api", "module_version"),
        (harmless_mod, "harmless_verifier", "available"),
        (harmless_mod, "harmless_verifier", "self_check"),
        (harmless_mod, "harmless_verifier", "module_version"),
    ]

    missing: list[str] = []
    for mod, name, func_name in modules_and_funcs:
        if not hasattr(mod, func_name):
            missing.append(f"{name}.{func_name}")

    assert not missing, f"Missing exports: {missing}"
