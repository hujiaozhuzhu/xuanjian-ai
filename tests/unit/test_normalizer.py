"""
结果归一化器单元测试
"""

from fp_sentinel.scanners.normalizer import ResultNormalizer
from fp_sentinel.models import ScanResult, ScanTool, Severity


class TestResultNormalizer:
    """归一化器测试"""

    def setup_method(self):
        self.normalizer = ResultNormalizer()

    def test_normalize_batch(self):
        """批量归一化"""
        scans = [
            ScanResult(
                tool=ScanTool.JS_SCANNER,
                rule_id=f"js.test.{i}",
                file="app.js",
                line=i * 10,
                code=f"code {i}",
                severity=Severity.MEDIUM,
                message=f"test {i}",
            )
            for i in range(5)
        ]
        findings = self.normalizer.normalize_many(scans)
        assert len(findings) == 5

    def test_normalize_batch_with_metadata(self):
        """带元数据的批量归一化"""
        scans = [
            ScanResult(
                tool=ScanTool.JS_SCANNER,
                rule_id="js.xss.innerhtml",
                file="app.js",
                line=10,
                code="test",
                severity=Severity.HIGH,
                message="test",
                metadata={"confidence": 0.8, "category": "XSS", "language": "javascript"},
            )
        ]
        findings = self.normalizer.normalize_many(scans)
        assert len(findings) == 1
        assert findings[0].confidence == 0.8

    def test_normalize_empty_batch(self):
        """空批量归一化"""
        findings = self.normalizer.normalize_many([])
        assert len(findings) == 0

    def test_keeps_distinct_minified_locations_with_same_code(self):
        scans = [
            ScanResult(
                tool=ScanTool.JS_SCANNER,
                rule_id="js.injection.eval",
                file="bundle.js",
                line=1,
                code="eval(userInput);",
                severity=Severity.CRITICAL,
                message="unsafe eval",
                metadata={
                    "beautified_line": formatted_line,
                    "original_offset_hint": {"original_start": original_offset},
                },
            )
            for formatted_line, original_offset in ((12, 32), (48, 192))
        ]

        findings = self.normalizer.normalize_many(scans)
        unique = self.normalizer.deduplicate(findings)

        assert len(unique) == 2
        assert unique[0].fingerprint != unique[1].fingerprint

    def test_normalize_batch_multiple(self):
        """批量归一化多条"""
        scans = [
            ScanResult(
                tool=ScanTool.JS_SCANNER,
                rule_id=f"js.test.{i}",
                file="app.js",
                line=i * 10,
                code=f"code {i}",
                severity=Severity.MEDIUM,
                message=f"test {i}",
            )
            for i in range(3)
        ]
        findings = self.normalizer.normalize_many(scans)
        assert len(findings) == 3
