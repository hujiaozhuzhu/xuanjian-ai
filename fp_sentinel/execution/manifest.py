"""Offline execution manifest helpers.

The execution gate produces an in-memory manifest before a scan starts.  This
module intentionally has no filesystem writes, subprocesses, or network
clients: callers can persist the returned mapping when their execution policy
allows it.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, MutableMapping, Sequence

STATUS_PASSED = "passed"
STATUS_FAIL_CLOSED = "fail_closed"
MANIFEST_VERSION = "1"


def utc_now() -> str:
    """Return a stable, UTC ISO-8601 timestamp."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_json(value: Any) -> bytes:
    """Serialize a JSON-compatible value deterministically for hashing."""
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    """Return a lowercase SHA-256 digest."""
    return hashlib.sha256(value).hexdigest()


def hash_rules(rules_dir: str | os.PathLike[str] | None) -> str:
    """Hash all rule files in deterministic relative-path order.

    The hash includes each relative path and its bytes.  Missing or empty rule
    directories hash to SHA-256 of an empty byte string; the caller records the
    missing-directory failure separately in the manifest limitations.
    """
    root = Path(rules_dir) if rules_dir is not None else None
    digest = hashlib.sha256()
    if root is None or not root.is_dir():
        return digest.hexdigest()
    for path in sorted(p for p in root.rglob("*") if p.is_file() and not p.is_symlink()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        content = path.read_bytes()
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _manifest_payload(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Return manifest fields covered by ``manifest_sha256``."""
    return {key: value for key, value in manifest.items() if key != "manifest_sha256"}


def calculate_manifest_sha256(manifest: Mapping[str, Any]) -> str:
    """Calculate the digest for a manifest, ignoring its existing digest."""
    return sha256_bytes(canonical_json(_manifest_payload(manifest)))


def verify_manifest(manifest: Mapping[str, Any]) -> bool:
    """Check that a manifest contains a matching integrity digest."""
    supplied = manifest.get("manifest_sha256")
    return isinstance(supplied, str) and supplied == calculate_manifest_sha256(manifest)


def generate_manifest(
    *,
    run_id: str | None = None,
    route: Any = "scan",
    rules_hash: str | None = None,
    module_versions: Mapping[str, str] | None = None,
    status: str = STATUS_PASSED,
    timestamps: Mapping[str, str] | None = None,
    limitations: Sequence[str] | None = None,
    self_check: Mapping[str, Any] | None = None,
    evidence: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a deterministic, integrity-protected execution manifest.

    ``timestamps`` may provide ``started_at`` and/or ``finished_at``.  Missing
    values are filled locally; no clock service or network call is involved.
    """
    now = utc_now()
    ts = {
        "started_at": now,
        "finished_at": now,
    }
    if timestamps:
        ts.update({str(key): str(value) for key, value in timestamps.items()})
    manifest: dict[str, Any] = {
        "manifest_version": MANIFEST_VERSION,
        "run_id": run_id or str(uuid.uuid4()),
        "route": route,
        "rules_hash": rules_hash or sha256_bytes(b""),
        "module_versions": dict(sorted((module_versions or {}).items())),
        "status": status,
        "timestamps": ts,
        "limitations": list(limitations or []),
    }
    manifest["manifest_sha256"] = calculate_manifest_sha256(manifest)
    return manifest


# A short alias keeps call sites readable while preserving an explicit name for
# callers that want to distinguish creation from verification.
create_manifest = generate_manifest


__all__ = [
    "MANIFEST_VERSION",
    "STATUS_FAIL_CLOSED",
    "STATUS_PASSED",
    "calculate_manifest_sha256",
    "canonical_json",
    "create_manifest",
    "generate_manifest",
    "hash_rules",
    "sha256_bytes",
    "utc_now",
    "verify_manifest",
]
