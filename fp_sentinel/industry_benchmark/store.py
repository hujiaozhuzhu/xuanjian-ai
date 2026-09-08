"""
玄鉴 v3.0 - Industry Benchmark :: SQLite Storage

SQLite-backed persistent storage for benchmark datasets and analysis records.

Security S7: DB path fixed to ~/.xuanjian/benchmark.db
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from .models import (
    BenchmarkDataset,
    CrossIndustryReport,
    GapAnalysisReport,
    Industry,
)


_DB_DIR = Path.home() / ".xuanjian"
_DB_PATH = _DB_DIR / "benchmark.db"


def _create_connection(path: str) -> sqlite3.Connection:
    """Create a new database connection"""
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _init_schema(conn: sqlite3.Connection) -> None:
    """Initialize database schema"""
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS benchmarks (
            industry TEXT PRIMARY KEY,
            version TEXT NOT NULL,
            data_json TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS gap_reports (
            report_id TEXT PRIMARY KEY,
            industry TEXT NOT NULL,
            enterprise_name TEXT DEFAULT '',
            data_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS cross_reports (
            report_id TEXT PRIMARY KEY,
            data_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS update_log (
            record_id TEXT PRIMARY KEY,
            source_id TEXT NOT NULL,
            industry TEXT NOT NULL,
            success INTEGER NOT NULL DEFAULT 1,
            changes_summary TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );
        """
    )
    conn.commit()


def _ensure_db_dir() -> None:
    """Ensure database directory exists"""
    _DB_DIR.mkdir(parents=True, exist_ok=True)


class BenchmarkStore:
    """Benchmark data persistent storage"""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        """
        Initialize store.

        Args:
            db_path: Optional custom DB path (for testing).
                     Default: ~/.xuanjian/benchmark.db
        """
        if db_path is not None:
            self._db_path = db_path
        else:
            self._db_path = _DB_PATH
            _ensure_db_dir()
        self._conn: Optional[sqlite3.Connection] = None

    @property
    def _connection(self) -> sqlite3.Connection:
        """Get or create instance-level connection"""
        if self._conn is None:
            self._conn = _create_connection(str(self._db_path))
            _init_schema(self._conn)
        return self._conn

    def close(self) -> None:
        """Close database connection"""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "BenchmarkStore":
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit - close connection"""
        self.close()

    # --- Benchmark CRUD ---

    def save_benchmark(self, dataset: BenchmarkDataset) -> None:
        """Save or update a benchmark dataset"""
        conn = self._connection
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """
            INSERT OR REPLACE INTO benchmarks (industry, version, data_json, updated_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                dataset.industry.value,
                dataset.version,
                dataset.model_dump_json(),
                now,
            ),
        )
        conn.commit()

    def load_benchmark(self, industry: Industry) -> Optional[BenchmarkDataset]:
        """Load a benchmark dataset by industry"""
        conn = self._connection
        row = conn.execute(
            "SELECT data_json FROM benchmarks WHERE industry = ?",
            (industry.value,),
        ).fetchone()
        if row is None:
            return None
        return BenchmarkDataset.model_validate_json(row["data_json"])

    def load_all_benchmarks(self) -> Dict[Industry, BenchmarkDataset]:
        """Load all benchmark datasets"""
        conn = self._connection
        rows = conn.execute("SELECT industry, data_json FROM benchmarks").fetchall()
        result: Dict[Industry, BenchmarkDataset] = {}
        for row in rows:
            try:
                ind = Industry(row["industry"])
                result[ind] = BenchmarkDataset.model_validate_json(row["data_json"])
            except (ValueError, KeyError):
                continue
        return result

    def list_stored_industries(self) -> List[Industry]:
        """List all stored industries"""
        conn = self._connection
        rows = conn.execute(
            "SELECT industry FROM benchmarks ORDER BY industry"
        ).fetchall()
        result: List[Industry] = []
        for row in rows:
            try:
                result.append(Industry(row["industry"]))
            except ValueError:
                continue
        return result

    # --- Gap Report CRUD ---

    def save_gap_report(self, report: GapAnalysisReport) -> None:
        """Save a gap analysis report"""
        conn = self._connection
        conn.execute(
            """
            INSERT OR REPLACE INTO gap_reports
            (report_id, industry, enterprise_name, data_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                report.report_id,
                report.industry.value,
                report.enterprise_name,
                report.model_dump_json(),
                report.generated_at,
            ),
        )
        conn.commit()

    def load_gap_report(self, report_id: str) -> Optional[GapAnalysisReport]:
        """Load a gap analysis report by ID"""
        conn = self._connection
        row = conn.execute(
            "SELECT data_json FROM gap_reports WHERE report_id = ?",
            (report_id,),
        ).fetchone()
        if row is None:
            return None
        return GapAnalysisReport.model_validate_json(row["data_json"])

    def list_gap_reports(self, industry: Optional[Industry] = None) -> List[str]:
        """List gap report IDs, optionally filtered by industry"""
        conn = self._connection
        if industry is not None:
            rows = conn.execute(
                "SELECT report_id FROM gap_reports WHERE industry = ? ORDER BY created_at DESC",
                (industry.value,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT report_id FROM gap_reports ORDER BY created_at DESC"
            ).fetchall()
        return [row["report_id"] for row in rows]

    # --- Cross-Industry Report CRUD ---

    def save_cross_report(self, report: CrossIndustryReport) -> None:
        """Save a cross-industry comparison report"""
        conn = self._connection
        conn.execute(
            """
            INSERT OR REPLACE INTO cross_reports (report_id, data_json, created_at)
            VALUES (?, ?, ?)
            """,
            (report.report_id, report.model_dump_json(), report.generated_at),
        )
        conn.commit()

    def load_cross_report(self, report_id: str) -> Optional[CrossIndustryReport]:
        """Load a cross-industry report"""
        conn = self._connection
        row = conn.execute(
            "SELECT data_json FROM cross_reports WHERE report_id = ?",
            (report_id,),
        ).fetchone()
        if row is None:
            return None
        return CrossIndustryReport.model_validate_json(row["data_json"])

    # --- Update Log ---

    def log_update(self, record_id: str, source_id: str, industry: Industry,
                   success: bool = True, changes_summary: str = "") -> None:
        """Log an update operation"""
        conn = self._connection
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """
            INSERT OR REPLACE INTO update_log
            (record_id, source_id, industry, success, changes_summary, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (record_id, source_id, industry.value, int(success), changes_summary, now),
        )
        conn.commit()

    def cleanup_old_records(self, retention_days: int = 180) -> int:
        """Remove update logs older than retention period (S5 compliance)"""
        from datetime import timedelta
        conn = self._connection
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        cursor = conn.execute(
            "DELETE FROM update_log WHERE created_at < ?", (cutoff,)
        )
        conn.commit()
        return cursor.rowcount or 0


def open_benchmark_store(db_path: Optional[Path] = None) -> BenchmarkStore:
    """Factory function to open a benchmark store"""
    return BenchmarkStore(db_path=db_path)
