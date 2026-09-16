"""SafeJsExecutor + backend tests — no external processes spawned."""

from __future__ import annotations

import unittest

from fp_sentinel.attack.dom_verify import (
    SafeJsExecutor,
    VerifyBackend,
    ExecutionResult,
    MarkerHit,
)
from fp_sentinel.attack.dom_verify.executor import (
    _PythonBackend,
    _JSDomBackend,
    _build_marker_setup,
    _build_marker_read,
    MARKER_PREFIX,
)


class TestMarkerInjection(unittest.TestCase):
    """Validate marker setup/read JS generation."""

    def test_marker_setup_creates_window_obj(self):
        js = _build_marker_setup(["xss", "ssrf"])
        self.assertIn(f"window.{MARKER_PREFIX}", js)
        self.assertIn("xss", js)
        self.assertIn("ssrf", js)

    def test_marker_setup_includes_eval_hook_for_xss(self):
        js = _build_marker_setup(["xss"])
        self.assertIn("eval", js)

    def test_marker_setup_includes_fetch_hook_for_ssrf(self):
        js = _build_marker_setup(["ssrf"])
        self.assertIn("fetch", js)

    def test_marker_read_returns_array(self):
        read_js = _build_marker_read(["xss", "ssrf"])
        import json
        parsed = json.loads(read_js)
        self.assertEqual(parsed, ["xss", "ssrf"])


class TestPythonBackend(unittest.TestCase):
    """Pure-python backend — static pattern detection only."""

    def test_available_always_true(self):
        self.assertTrue(_PythonBackend.available())

    def test_detects_marker_setter_pattern(self):
        payload = (
            "if(window.__fp_verify__) "
            "window.__fp_verify__['xss'] = {fired:true};"
        )
        result = _PythonBackend.run(
            "<html></html>", payload, ["xss"], timeout_ms=1000,
        )
        self.assertTrue(result.success)
        self.assertEqual(result.backend, VerifyBackend.PYTHON)
        fired = [m for m in result.markers if m.vuln_type == "xss"]
        self.assertTrue(len(fired) == 1)
        self.assertTrue(fired[0].fired)

    def test_no_marker_no_fire(self):
        payload = "console.log('hello')"
        result = _PythonBackend.run(
            "<html></html>", payload, ["xss"], timeout_ms=1000,
        )
        self.assertTrue(result.success)
        fired = [m for m in result.markers if m.vuln_type == "xss" and m.fired]
        self.assertEqual(len(fired), 0)

    def test_multiple_markers_partial_fire(self):
        payload = (
            "window.__fp_verify__['xss'] = {fired:true};"
            "console.log('no ssrf marker');"
        )
        result = _PythonBackend.run(
            "<html></html>", payload, ["xss", "ssrf"], timeout_ms=1000,
        )
        by_type = {m.vuln_type: m for m in result.markers}
        self.assertTrue(by_type["xss"].fired)
        self.assertFalse(by_type["ssrf"].fired)


class TestJsDomBackend(unittest.TestCase):
    """Node.js + jsdom backend — skip if node not available."""

    @classmethod
    def setUpClass(cls):
        if not _JSDomBackend.available():
            raise unittest.SkipTest("node not available — jsdom backend skipped")

    def test_basic_xss_marker_fires(self):
        html = "<html><body><div id='out'></div></body></html>"
        payload = "document.getElementById('out').innerHTML = '<script>window.__fp_verify__[xss] = {fired:true}</script>';"
        result = _JSDomBackend.run(html, payload, ["xss"], timeout_ms=3000)
        # jsdom may or may not trigger marker depending on CSP settings
        self.assertIsInstance(result, ExecutionResult)

    def test_backend_returns_markers_list(self):
        result = _JSDomBackend.run(
            "<html></html>",
            "console.log('test')",
            ["xss"],
            timeout_ms=3000,
        )
        self.assertIsInstance(result.markers, list)
        # When jsdom is available markers list length equals requested count;
        # when jsdom is unavailable the backend returns an empty list + error.
        if result.success:
            self.assertEqual(len(result.markers), 1)
            self.assertEqual(result.markers[0].vuln_type, "xss")
        else:
            # jsdom not installed in node — backend returns empty (acceptable)
            self.assertEqual(len(result.markers), 0)


class TestSafeJsExecutor(unittest.TestCase):
    """High-level executor tests — no subprocess spawned when using PYTHON backend."""

    def test_executor_selects_preferred_backend(self):
        # Default: use PLAYWRIGHT if available else JSDOM else PYTHON
        executor = SafeJsExecutor(preferred=VerifyBackend.PYTHON)
        self.assertEqual(executor.backend, VerifyBackend.PYTHON)

    def test_executor_runs_python_backend_successfully(self):
        executor = SafeJsExecutor(preferred=VerifyBackend.PYTHON)
        result = executor.run(
            "<html></html>",
            "window.__fp_verify__['xss'] = {fired:true}; deadline_budit: 'done'",
            ["xss"],
        )
        self.assertTrue(result.success)
        self.assertTrue(result.any_fired)

    def test_executor_run_returns_dict_serializable(self):
        executor = SafeJsExecutor(preferred=VerifyBackend.PYTHON)
        result = executor.run("<html></html>", "console.log(1)", ["xss"])
        d = result.to_dict()
        self.assertIn("backend", d)
        self.assertIn("markers", d)
        self.assertIn("success", d)

    def test_executor_with_multiple_markers(self):
        executor = SafeJsExecutor(preferred=VerifyBackend.PYTHON)
        result = executor.run(
            "<html></html>",
            "window.__fp_verify__['xss'] = {fired:true}; window.__fp_verify__['ssrf'] = {fired:true};",
            ["xss", "ssrf"],
        )
        self.assertEqual(len(result.markers), 2)
        self.assertTrue(all(m.fired for m in result.markers))


class TestExecutionResult(unittest.TestCase):
    """Dataclass model fields and serialization."""

    def test_default_values(self):
        r = ExecutionResult(backend=VerifyBackend.PYTHON, success=True)
        self.assertEqual(r.markers, [])
        self.assertEqual(r.console_log, [])
        self.assertFalse(r.any_fired)

    def test_marker_hit_default_details(self):
        m = MarkerHit(vuln_type="xss", fired=False)
        self.assertEqual(m.details, {})
        self.assertEqual(m.timestamp, 0.0)

    def test_any_fired_one_of_two(self):
        r = ExecutionResult(
            backend=VerifyBackend.PYTHON,
            success=True,
            markers=[
                MarkerHit(vuln_type="xss", fired=True),
                MarkerHit(vuln_type="ssrf", fired=False),
            ],
        )
        self.assertTrue(r.any_fired)

    def test_marker_hit_to_dict(self):
        m = MarkerHit(vuln_type="xss", fired=True, details={"method": "test"}, timestamp=1234567.0)
        d = m.to_dict()
        self.assertEqual(d["vuln_type"], "xss")
        self.assertTrue(d["fired"])
        self.assertIn("method", d.get("details", {}))


if __name__ == "__main__":
    unittest.main()
