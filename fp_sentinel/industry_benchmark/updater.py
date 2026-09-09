"""
玄鉴 v3.0 - Industry Benchmark :: Data Updater

Manages benchmark data updates with S1/S5/S6/S7 compliance:
- S1: Update operations are optional and mockable (no network in tests)
- S5: Configurable retention policy for update history
- S7: DB path fixed to ~/.xuanjian/
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .models import (
    BenchmarkDataset,
    Industry,
    UpdatePolicy,
    UpdateRecord,
    UpdateSource,
)
from .builtin_data import build_benchmark_dataset


# Default update sources (informational display only)
_DEFAULT_SOURCES: List[UpdateSource] = [
    UpdateSource(
        source_id="cnvd",
        name="CNVD - China National Vulnerability Database",
        url="https://www.cnvd.org.cn",
        description="Chinese national vulnerability repository",
        enabled=False,
    ),
    UpdateSource(
        source_id="cnnvd",
        name="CNNVD - China National Vulnerability Database of Information Security",
        url="https://www.cnnvd.org.cn",
        description="Chinese NVD equivalent for IT products",
        enabled=False,
    ),
    UpdateSource(
        source_id="nvd",
        name="NVD - National Vulnerability Database",
        url="https://nvd.nist.gov",
        description="US National Vulnerability Database (CVE source)",
        enabled=False,
    ),
]


class BenchmarkUpdater:
    """
    Manages benchmark dataset updates.

    Security compliance:
    - S1: Network access is optional (sources disabled by default)
    - S3: Only touches data within benchmark DB, never modifies target code
    - S5: Retention policy auto-applied to old records
    """

    def __init__(self, policy: Optional[UpdatePolicy] = None,
                 store=None) -> None:
        """
        Initialize updater.

        Args:
            policy: Update policy. If None, uses default (auto_update=False).
            store: Optional BenchmarkStore instance.
        """
        self._policy = policy or create_default_policy()
        self._store = store

    @property
    def policy(self) -> UpdatePolicy:
        return self._policy

    @policy.setter
    def policy(self, value: UpdatePolicy) -> None:
        self._policy = value

    def import_builtin_data(self, industry: Industry) -> UpdateRecord:
        """
        Import benchmark data from built-in dataset (offline, always works).

        Args:
            industry: Target industry

        Returns:
            Update record
        """
        dataset = build_benchmark_dataset(industry)
        record_id = f"upd-{uuid.uuid4().hex[:12]}"

        if self._store is not None:
            self._store.save_benchmark(dataset)
            self._store.log_update(
                record_id=record_id,
                source_id="builtin",
                industry=industry,
                success=True,
                changes_summary=f"Imported built-in dataset v{dataset.version} for {industry.value}",
            )

        return UpdateRecord(
            record_id=record_id,
            source_id="builtin",
            industry=industry,
            changes_summary=f"Imported {len(dataset.vuln_distribution)} categories, "
                           f"{len(dataset.top_vulnerabilities)} top vulns",
            success=True,
        )

    def import_all_builtin(self) -> Dict[Industry, UpdateRecord]:
        """Import built-in benchmark data for all industries"""
        records: Dict[Industry, UpdateRecord] = {}
        for industry in Industry:
            records[industry] = self.import_builtin_data(industry)
        return records

    def refresh_industry(self, industry: Industry) -> UpdateRecord:
        """
        Refresh benchmark data for an industry.

        If policy.auto_update is True and sources are enabled,
        this would fetch from external sources (not implemented).
        Otherwise, falls back to built-in data import.

        Args:
            industry: Target industry

        Returns:
            Update record
        """
        has_external_source = any(
            s.enabled for s in self._policy.sources
        )

        if self._policy.auto_update and has_external_source:
            # External fetching is intentionally not implemented.
            # Users can inject a provider if needed.
            return self._attempt_external_update(industry)

        return self.import_builtin_data(industry)

    def _attempt_external_update(self, industry: Industry) -> UpdateRecord:
        """
        Attempt to update from external source (stub).

        In production this would use an injected HTTP provider.
        For safety/s1 compliance, this is a stub that returns failure.
        """
        record_id = f"upd-{uuid.uuid4().hex[:12]}"
        record = UpdateRecord(
            record_id=record_id,
            source_id="external",
            industry=industry,
            changes_summary="External update not implemented (S1 compliance)",
            success=False,
        )
        if self._store is not None:
            self._store.log_update(
                record_id=record_id,
                source_id="external",
                industry=industry,
                success=False,
                changes_summary="External update not implemented",
            )
        return record

    def cleanup_old_records(self) -> int:
        """Apply retention policy to old update records (S5)"""
        if self._store is None:
            return 0
        return self._store.cleanup_old_records(self._policy.retention_days)

    def get_update_history(self, industry: Optional[Industry] = None) -> List[str]:
        """Get update history record IDs"""
        if self._store is None:
            return []
        return self._store.list_gap_reports(industry=industry)


def create_default_policy() -> UpdatePolicy:
    """
    Create a default safe update policy.

    - auto_update=False (no unexpected network calls)
    - retention_days=180 (S5 compliance)
    - All external sources disabled
    """
    return UpdatePolicy(
        auto_update=False,
        interval_days=30,
        retention_days=180,
        sources=list(_DEFAULT_SOURCES),
    )


def create_aggressive_policy(interval_days: int = 7,
                              retention_days: int = 90) -> UpdatePolicy:
    """Create an aggressive update policy (auto_update enabled)"""
    return UpdatePolicy(
        auto_update=True,
        interval_days=interval_days,
        retention_days=retention_days,
        sources=[s.model_copy(update={"enabled": True}) for s in _DEFAULT_SOURCES],
    )
