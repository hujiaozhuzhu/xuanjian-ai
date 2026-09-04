"""
A6-2. 合规报告测试（趋势 / fingerprint 对比 / ROI / Diff 块）
"""

from fp_sentinel.database import get_database, FindingRepo, ScanHistoryRepo
from fp_sentinel.models import Finding, Severity
from fp_sentinel.reporting.compliance_report import (
    compute_trend,
    generate_compliance_report,
)


def _mk_finding(fp: str, rule_id: str, severity=Severity.HIGH, line=10):
    return Finding(
        scanner="python_scanner",
        rule_id=rule_id,
        severity=severity,
        file_path="app.py",
        line_start=line,
        code_snippet=f"# snippet {rule_id}",
        fingerprint=fp,
    )


async def _seed(db, findings_by_scan: dict):
    fr = FindingRepo(db)
    hr = ScanHistoryRepo(db)
    scan_ids = {}
    for project_path, scan_name in [("proj", None)][:0]:
        pass
    for scan_name, findings in findings_by_scan.items():
        h = await hr.create(project_path="proj", scanner="test", total_findings=len(findings))
        scan_ids[scan_name] = h.scan_id
        await fr.bulk_create(findings, scan_id=h.scan_id)
    return scan_ids


class TestTrend:
    async def test_first_scan_is_baseline(self, tmp_path):
        async with get_database(str(tmp_path / "t.db")) as db:
            scan_ids = await _seed(db, {
                "first": [_mk_finding("fp1", "py.injection.sql")],
            })
            trend = await compute_trend(
                FindingRepo(db), ScanHistoryRepo(db), "proj",
                current_scan_id=scan_ids["first"],
            )
            assert trend["is_baseline"] is True

    async def test_new_fixed_remaining(self, tmp_path):
        """fingerprint 对比：新增/修复/遗留"""
        async with get_database(str(tmp_path / "t.db")) as db:
            scan_ids = await _seed(db, {
                "first": [
                    _mk_finding("fp1", "py.injection.sql"),
                    _mk_finding("fp2", "py.xss.dom"),
                ],
                "second": [
                    _mk_finding("fp2", "py.xss.dom"),        # 遗留
                    _mk_finding("fp3", "py.injection.command"),  # 新增
                ],
            })
            trend = await compute_trend(
                FindingRepo(db), ScanHistoryRepo(db), "proj",
                current_scan_id=scan_ids["second"],
            )
            assert trend["is_baseline"] is False
            new_fps = {f.fingerprint for f in trend["new"]}
            fixed_fps = {f.fingerprint for f in trend["fixed"]}
            remain_fps = {f.fingerprint for f in trend["remaining"]}
            assert new_fps == {"fp3"}
            assert fixed_fps == {"fp1"}
            assert remain_fps == {"fp2"}

    async def test_uses_project_history_beyond_global_limit(self, tmp_path):
        """项目历史必须在数据库层过滤，不能被其他项目的记录截断。"""
        async with get_database(str(tmp_path / "t.db")) as db:
            fr = FindingRepo(db)
            hr = ScanHistoryRepo(db)
            first = await hr.create(project_path="proj", scanner="test")
            await fr.bulk_create([_mk_finding("fp1", "py.injection.sql")], scan_id=first.scan_id)
            for _ in range(201):
                await hr.create(project_path="other", scanner="test")
            second = await hr.create(project_path="proj", scanner="test")
            await fr.bulk_create([_mk_finding("fp2", "py.xss.dom")], scan_id=second.scan_id)

            trend = await compute_trend(fr, hr, "proj", current_scan_id=second.scan_id)

            assert trend["is_baseline"] is False
            assert {f.fingerprint for f in trend["new"]} == {"fp2"}
            assert {f.fingerprint for f in trend["fixed"]} == {"fp1"}

    async def test_uses_supplied_findings_when_scan_is_not_saved(self, tmp_path):
        """未持久化扫描仍应与最近一次历史结果做正确的趋势比较。"""
        async with get_database(str(tmp_path / "t.db")) as db:
            fr = FindingRepo(db)
            hr = ScanHistoryRepo(db)
            previous = await hr.create(project_path="proj", scanner="test")
            await fr.bulk_create([_mk_finding("fp1", "py.injection.sql")], scan_id=previous.scan_id)
            current = [_mk_finding("fp2", "py.xss.dom")]

            trend = await compute_trend(fr, hr, "proj", current_findings=current)

            assert trend["is_baseline"] is False
            assert {f.fingerprint for f in trend["new"]} == {"fp2"}
            assert {f.fingerprint for f in trend["fixed"]} == {"fp1"}


class TestReportContent:
    def _mk_trend(self, baseline=False):
        if baseline:
            return {
                "is_baseline": True,
                "current": {"total": 3, "by_severity": {"HIGH": 2, "MEDIUM": 1}},
                "previous": {"total": 0, "by_severity": {}},
                "new": [], "fixed": [], "remaining": [],
                "previous_scan_id": None, "previous_time": None,
            }
        return {
            "is_baseline": False,
            "current": {"total": 3, "by_severity": {"HIGH": 2, "MEDIUM": 1}},
            "previous": {"total": 4, "by_severity": {"HIGH": 3, "LOW": 1}},
            "new": [_mk_finding("fp3", "py.injection.command")],
            "fixed": [_mk_finding("fp1", "py.injection.sql")],
            "remaining": [_mk_finding("fp2", "py.xss.dom")],
            "previous_scan_id": "prev", "previous_time": "2026-08-01",
        }

    def test_baseline_report(self):
        md = generate_compliance_report(
            project="demo", project_path="/tmp/demo",
            trend=self._mk_trend(baseline=True),
            findings=[_mk_finding("fp1", "py.injection.sql")],
        )
        assert "首期基线" in md
        assert "① 趋势对比" in md
        assert "② 需关注" in md
        assert "③ Diff 修复建议" in md

    def test_trend_table_counts(self):
        md = generate_compliance_report(
            project="demo", project_path="/tmp/demo",
            trend=self._mk_trend(),
            findings=[
                _mk_finding("fp2", "py.xss.dom"),
                _mk_finding("fp3", "py.injection.command"),
            ],
        )
        assert "新增 **1**" in md
        assert "已修复 **1**" in md
        assert "遗留 **1**" in md
        assert "| 总发现数 | 3 | 4 | -1 |" in md

    def test_diff_blocks_present(self):
        md = generate_compliance_report(
            project="demo", project_path="/tmp/demo",
            trend=self._mk_trend(),
            findings=[
                _mk_finding("fp2", "py.xss.dom"),
                _mk_finding("fp3", "py.injection.sql"),
            ],
        )
        assert "```diff" in md
        assert "safe_load" not in md or "```diff" in md
        assert "不会修改您的源文件" in md

    def test_roi_order(self):
        """高危且低工时的排在前面"""
        from fp_sentinel.reporting.compliance_report import _roi_sort_key
        from fp_sentinel.reporting.fix_advisor import suggest_fix
        crit = _mk_finding("a", "py.injection.sql", Severity.CRITICAL)
        low = _mk_finding("b", "py.auth.debug_mode", Severity.LOW)
        pairs = [(low, suggest_fix(low)), (crit, suggest_fix(crit))]
        pairs.sort(key=_roi_sort_key)
        assert pairs[0][0].fingerprint == "a"

    def test_no_file_modification(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text("yaml.load(d)\n", encoding="utf-8")
        before = src.read_text(encoding="utf-8")
        generate_compliance_report(
            project="demo", project_path=str(tmp_path),
            trend=self._mk_trend(),
            findings=[_mk_finding("fp2", "py.deserialization.yaml")],
        )
        assert src.read_text(encoding="utf-8") == before
