"""Offline, read-only execution preflight gate.

``preflight`` validates the local skill package and module contracts before a
scan is allowed to start.  It invokes each module's local ``available`` and
``self_check`` contracts, but never performs network, subprocess, or write
operations.  A missing or malformed prerequisite returns ``status=fail_closed``
so callers can stop without guessing a fallback.
"""

from __future__ import annotations

import importlib
import os
from pathlib import Path
from typing import Any, Mapping, Sequence

from .manifest import (
    STATUS_FAIL_CLOSED,
    STATUS_PASSED,
    create_manifest,
    hash_rules,
    utc_now,
)

DEFAULT_MODULES: tuple[str, ...] = (
    "fp_sentinel.attack.dom_verify.executor",
    "fp_sentinel.api_knowledge.store",
    "fp_sentinel.api_knowledge.associator",
    "fp_sentinel.web_api.api_discovery",
    "fp_sentinel.attack.harmless_verifier.verifier",
)
REQUIRED_MODULE_CONTRACT: tuple[str, ...] = ("available", "self_check", "module_version")
ROUTING_TABLE_NAME = "01-routing-table.yaml"


class PreflightError(RuntimeError):
    """Raised by ``require_preflight`` when execution must stop."""

    def __init__(self, manifest: Mapping[str, Any]):
        self.manifest = dict(manifest)
        limitations = self.manifest.get("limitations") or ["preflight failed"]
        super().__init__("execution preflight failed closed: " + "; ".join(map(str, limitations)))


def _resolve_skill_root(skill_root: str | os.PathLike[str] | None) -> Path:
    if skill_root is not None:
        return Path(skill_root).expanduser()
    env_root = os.environ.get("FP_SKILL_ROOT")
    if env_root:
        return Path(env_root).expanduser()
    return Path.home() / ".meituan-catpaw" / "4275287949" / "skills" / "fp_sentinel"


def _parse_routing_table(path: Path) -> tuple[bool, str]:
    """Parse the routing table without requiring a YAML dependency.

    The shipped table is a rule document with YAML extension rather than a
    mapping.  It is valid when it is readable, non-empty UTF-8 text; if a real
    YAML mapping/list is supplied, use PyYAML when available and reject malformed
    syntax when PyYAML is present.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return False, f"routing table unreadable: {exc}"
    if not text.strip():
        return False, "routing table is empty"
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        # Offline validation remains possible for the repository's rule-document
        # form.  Do not install or fetch a parser during preflight.
        return True, "routing table text parsed (PyYAML unavailable)"
    try:
        parsed = yaml.safe_load(text)
    except Exception as exc:  # PyYAML YAMLError varies across versions.
        return False, f"routing table parse failed: {exc}"
    if parsed is None:
        return False, "routing table parsed to empty document"
    if isinstance(parsed, (dict, list, str)):
        return True, "routing table parsed"
    return False, f"routing table has unsupported root type: {type(parsed).__name__}"


def _check_module_contracts(modules: Sequence[str]) -> tuple[dict[str, str], list[str]]:
    versions: dict[str, str] = {}
    failures: list[str] = []
    for module_name in modules:
        try:
            module = importlib.import_module(module_name)
        except Exception as exc:
            failures.append(f"module {module_name} import failed: {type(exc).__name__}: {exc}")
            continue
        missing = [name for name in REQUIRED_MODULE_CONTRACT if not callable(getattr(module, name, None))]
        if missing:
            failures.append(f"module {module_name} missing contract: {', '.join(missing)}")
            continue
        try:
            available = module.available()
        except Exception as exc:
            failures.append(
                f"module {module_name} available() raised {type(exc).__name__}: {exc}"
            )
            continue
        if available is not True:
            failures.append(f"module {module_name} available() returned {available!r}")
            continue
        try:
            check_result = module.self_check()
        except Exception as exc:
            failures.append(
                f"module {module_name} self_check() raised {type(exc).__name__}: {exc}"
            )
            continue
        check_ok: Any
        check_detail: Any = ""
        if isinstance(check_result, tuple):
            check_ok = check_result[0] if check_result else False
            check_detail = check_result[1] if len(check_result) > 1 else ""
        else:
            check_ok = check_result
        if check_ok is not True:
            detail = f": {check_detail}" if check_detail else ""
            failures.append(
                f"module {module_name} self_check() returned {check_result!r}{detail}"
            )
            continue
        try:
            version = module.module_version()
        except Exception as exc:
            failures.append(f"module {module_name} version lookup failed: {type(exc).__name__}: {exc}")
            continue
        if not isinstance(version, str) or not version.strip():
            failures.append(f"module {module_name} returned invalid module_version")
            continue
        versions[module_name] = version
    return versions, failures


def _failed_manifest(
    *,
    route: Any,
    rules_digest: str,
    versions: Mapping[str, str],
    limitations: Sequence[str],
    started_at: str,
) -> dict[str, Any]:
    return create_manifest(
        route=route,
        rules_hash=rules_digest,
        module_versions=versions,
        status=STATUS_FAIL_CLOSED,
        timestamps={"started_at": started_at, "finished_at": utc_now()},
        limitations=limitations,
    )


def preflight(
    skill_root: str | os.PathLike[str] | None = None,
    *,
    route: Any = "scan",
    modules: Sequence[str] = DEFAULT_MODULES,
) -> dict[str, Any]:
    """Run local preflight and return a manifest; never raises for gate errors.

    Success has ``status=passed``.  Any missing/unreadable/unparseable skill
    rule, routing table, or module contract yields ``status=fail_closed`` and a
    non-empty ``limitations`` list.  The function is read-only and offline.
    """
    started_at = utc_now()
    root = _resolve_skill_root(skill_root)
    rules_dir = root / "rules"
    routing_table = rules_dir / ROUTING_TABLE_NAME
    rules_digest = hash_rules(rules_dir)
    limitations: list[str] = []

    if not root.is_dir():
        limitations.append(f"skill root missing: {root}")
    if not rules_dir.is_dir():
        limitations.append(f"rules directory missing: {rules_dir}")
    if not routing_table.is_file():
        limitations.append(f"routing table missing: {routing_table}")
    elif routing_table.is_file():
        parsed, detail = _parse_routing_table(routing_table)
        if not parsed:
            limitations.append(detail)

    versions, contract_failures = _check_module_contracts(modules)
    limitations.extend(contract_failures)
    status = STATUS_PASSED if not limitations else STATUS_FAIL_CLOSED
    return create_manifest(
        route=route,
        rules_hash=rules_digest,
        module_versions=versions,
        status=status,
        timestamps={"started_at": started_at, "finished_at": utc_now()},
        limitations=limitations,
    )


def require_preflight(
    skill_root: str | os.PathLike[str] | None = None,
    *,
    route: Any = "scan",
    modules: Sequence[str] = DEFAULT_MODULES,
) -> dict[str, Any]:
    """Return a passing manifest or raise ``PreflightError`` fail-closed."""
    manifest = preflight(skill_root, route=route, modules=modules)
    if manifest["status"] != STATUS_PASSED:
        raise PreflightError(manifest)
    return manifest


# Compatibility spelling for callers that use the gate as a verb.
run_preflight = preflight


__all__ = [
    "DEFAULT_MODULES",
    "PreflightError",
    "REQUIRED_MODULE_CONTRACT",
    "ROUTING_TABLE_NAME",
    "preflight",
    "require_preflight",
    "run_preflight",
]
