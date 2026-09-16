"""report_builder.py 单元测试：多来源聚合 / 统计 / 输出。"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from fp_sentinel.mobile_reporting.models.report_models import FindingReport

from fp_sentinel.web_evidence.report_builder import WebEvidenceReportBuilder


# ────────────────────────── 辅助 ──────────────────────────


def _make_burp_file(tmp_path: Path, issues: list) -> Path:
    path = tmp_path / "burp.json"
    path.write_text(json.dumps(issues), encoding="utf-8")
    return path


def _make_nuclei_file(tmp_path: Path, results: list) -> Path:
    path = tmp_path / "nuclei.jsonl"
    path.write_text(
        "\n".join(json.dumps(r) for r in results),
        encoding="utf-8",
    )
    return path


def _make_zap_file(tmp_path: Path, alerts: list) -> Path:
    path = tmp_path / "zap.json"
    path.write_text(
        json.dumps({"site": [{"alerts": alerts}]}),
        encoding="utf-8",
    )
    return path


def _make_csv_file(tmp_path: Path, rows: list[dict]) -> Path:
    path = tmp_path / "manual.csv"
    if not rows:
        path.write_text(
            "id,title,severity,cwe_id,description,evidence,remediation\n",
            encoding="utf-8",
        )
        return path
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return path


# ────────────────────────── 构建与聚合 ──────────────────────────


class TestWebEvidenceReportBuilder:
    def test_add_single_finding(self) -> None:
        builder = WebEvidenceReportBuilder()
        finding = FindingReport(id="T1", title="测试", severity="HIGH")
        builder.add_finding(finding)
        assert len(builder._findings) == 1

    def test_add_findings_batch(self) -> None:
        builder = WebEvidenceReportBuilder()
        findings = [
            FindingReport(id=f"T{i}", title=f"漏洞{i}", severity="MEDIUM")
            for i in range(5)
        ]
        builder.add_findings(findings)
        assert len(builder._findings) == 5

    def test_add_none_ignored(self) -> None:
        builder = WebEvidenceReportBuilder()
        builder.add_finding(None)
        assert len(builder._findings) == 0

    def test_from_burp_json(self, tmp_path: Path) -> None:
        issues = [
            {
                "name": "SQL Injection", "host": "https://example.com",
                "path": "/api/v1/users", "severity": "High",
                "confidence": "Certain", "issueDetail": "CWE-89 注入",
                "remediationBackground": "参数化查询", "references": [],
            },
        ]
        path = _make_burp_file(tmp_path, issues)
        builder = WebEvidenceReportBuilder().add_from_burp_json(path)
        assert len(builder._findings) == 1
        assert builder._findings[0].severity == "HIGH"

    def test_from_nuclei_jsonl(self, tmp_path: Path) -> None:
        results = [
            {
                "template-id": "CVE-2023-1234",
                "matcher-name": "Apache LFI",
                "matched-at": "https://example.com/lfi",
                "info": {
                    "name": "Apache Path Traversal",
                    "severity": "critical",
                    "description": "Path traversal",
                    "tags": ["cve", "lfi"],
                },
            },
        ]
        path = _make_nuclei_file(tmp_path, results)
        builder = WebEvidenceReportBuilder().add_from_nuclei_json(path)
        assert len(builder._findings) == 1
        assert builder._findings[0].severity == "CRITICAL"

    def test_from_zap_json(self, tmp_path: Path) -> None:
        alerts = [
            {
                "name": "XSS", "riskdesc": "High", "cweid": "79",
                "desc": "CWE-79", "uri": "https://example.com/xss",
                "solution": "Filter input",
                "instances": [{"uri": "https://example.com/xss"}],
            },
        ]
        path = _make_zap_file(tmp_path, alerts)
        builder = WebEvidenceReportBuilder().add_from_zap_json(path)
        assert len(builder._findings) == 1
        assert builder._findings[0].severity == "HIGH"

    def test_from_csv(self, tmp_path: Path) -> None:
        rows = [
            {
                "id": "CSV-001", "title": "硬编码凭据",
                "severity": "HIGH", "cwe_id": "CWE-798",
                "description": "源码中硬编码密钥",
                "evidence": "config.py:12 SECRET_KEY = 'abc'",
                "remediation": "使用环境变量存储密钥",
            },
        ]
        path = _make_csv_file(tmp_path, rows)
        builder = WebEvidenceReportBuilder().add_from_csv(path)
        assert len(builder._findings) == 1
        assert builder._findings[0].severity == "HIGH"

    def test_from_paths_factory(self, tmp_path: Path) -> None:
        burp_issues = [
            {"name": "B1", "severity": "Medium", "issueDetail": "desc",
             "host": "http://a", "path": "/x", "confidence": "Certain"},
        ]
        csv_rows = [
            {"id": "C1", "title": "T1", "severity": "LOW", "cwe_id": "",
             "description": "d", "evidence": "e", "remediation": "r"},
        ]
        burp_path = _make_burp_file(tmp_path, burp_issues)
        csv_path = _make_csv_file(tmp_path, csv_rows)
        builder = WebEvidenceReportBuilder.from_paths(
            burp=burp_path, csv=csv_path,
        )
        assert len(builder._findings) == 2


# ────────────────────────── build / 统计 ──────────────────────────


class TestBuildAndStatistics:
    def test_build_creates_report(self) -> None:
        builder = WebEvidenceReportBuilder()
        builder.add_finding(
            FindingReport(id="T1", title="漏洞1", severity="HIGH"),
        )
        builder.add_finding(
            FindingReport(id="T2", title="漏洞2", severity="MEDIUM"),
        )
        builder.add_finding(
            FindingReport(id="T3", title="漏洞3", severity="HIGH"),
        )
        report = builder.build(target_app_name="example.com")
        assert report is not None
        assert len(report.findings) == 3
        assert report.statistics is not None
        assert report.statistics.total_count == 3
        assert report.statistics.by_severity.get("HIGH", 0) == 2
        assert report.statistics.by_severity.get("MEDIUM", 0) == 1

    def test_build_metadata(self) -> None:
        builder = WebEvidenceReportBuilder()
        builder.add_finding(
            FindingReport(id="T1", title="test", severity="HIGH"),
        )
        report = builder.build(
            target_app_name="mysite.com",
            scan_command="nuclei -t cves/",
        )
        assert "mysite.com" in report.metadata.title
        assert report.environment is not None
        assert report.environment.scan_command == "nuclei -t cves/"

    def test_build_empty_findings(self) -> None:
        builder = WebEvidenceReportBuilder()
        report = builder.build()
        assert report is not None
        assert len(report.findings) == 0
        assert report.statistics.total_count == 0

    def test_sources_tracked(self, tmp_path: Path) -> None:
        builder = WebEvidenceReportBuilder()
        burp_path = _make_burp_file(tmp_path, [
            {"name": "B1", "severity": "High", "issueDetail": "d",
             "host": "h", "path": "/p", "confidence": "Certain"},
        ])
        builder.add_from_burp_json(burp_path)
        assert builder._sources.get("burp", 0) == 1


# ────────────────────────── generate（mock 真实格式） ──────────────────────────


class TestGenerate:
    def test_generate_calls_report_module(
        self, tmp_path: Path,
    ) -> None:
        builder = WebEvidenceReportBuilder()
        builder.add_finding(
            FindingReport(id="T1", title="test", severity="HIGH"),
        )
        with patch(
            "fp_sentinel.mobile_reporting.generate_report",
            return_value={"html": str(tmp_path / "report.html")},
        ) as mock_gen:
            result = builder.generate(
                tmp_path,
                formats=("html",),
                target_app_name="example.com",
            )
            assert mock_gen.called
            assert "html" in result

    def test_generate_skips_when_openpyxl_unavailable(
        self, tmp_path: Path,
    ) -> None:
        builder = WebEvidenceReportBuilder()
        builder.add_finding(
            FindingReport(id="T1", title="test", severity="HIGH"),
        )
        with patch(
            "fp_sentinel.mobile_reporting.generate_report",
            side_effect=RuntimeError("Excel 生成器不可用"),
        ):
            with pytest.raises(RuntimeError):
                builder.generate(tmp_path, formats=("excel",))


# ────────────────────────── 错误处理 ──────────────────────────


class TestErrorHandling:
    def test_missing_file_skipped(self) -> None:
        builder = WebEvidenceReportBuilder()
        builder.add_from_burp_json("/nonexistent/path/file.json")
        assert len(builder._findings) == 0

    def test_invalid_json_skipped(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{invalid json", encoding="utf-8")
        builder = WebEvidenceReportBuilder()
        builder.add_from_burp_json(bad_file)
        assert len(builder._findings) == 0

    def test_csv_missing_file_skipped(self) -> None:
        builder = WebEvidenceReportBuilder()
        builder.add_from_csv("/nonexistent/report.csv")
        assert len(builder._findings) == 0

    def test_mixed_valid_invalid_findings(self, tmp_path: Path) -> None:
        issues = [
            {"name": "Valid", "severity": "High", "issueDetail": "d",
             "host": "h", "path": "/p", "confidence": "Certain"},
            "not a dict",
            {"name": "Also Valid", "severity": "Low", "issueDetail": "d2",
             "host": "h2", "path": "/x", "confidence": "Certain"},
        ]
        path = _make_burp_file(tmp_path, issues)
        builder = WebEvidenceReportBuilder().add_from_burp_json(path)
        assert len(builder._findings) == 2
