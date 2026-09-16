"""stealth.json profile loading tests."""

import json
from pathlib import Path


def test_stealth_profile_loads():
    """Verify stealth.json has all expected fields."""
    path = Path("fp_sentinel/browser/profiles/stealth.json")
    data = json.loads(path.read_text())
    assert "timezone" in data
    assert "locale" in data["timezone"]
    assert "canvas" in data
    assert "client_rects" in data
    assert "fonts" in data


def test_stealth_timezone_fields():
    """Verify timezone configuration is complete."""
    path = Path("fp_sentinel/browser/profiles/stealth.json")
    data = json.loads(path.read_text())
    tz = data["timezone"]
    assert tz["zone"] == "Asia/Shanghai"
    assert tz["offset"] == -480
    assert tz["locale"] == "zh-CN"


def test_stealth_navigator_fields():
    """Verify navigator configuration has anti-fingerprint fields."""
    path = Path("fp_sentinel/browser/profiles/stealth.json")
    data = json.loads(path.read_text())
    nav = data["navigator"]
    assert nav["platform"] == "Win32"
    assert len(nav["languages"]) >= 2
    assert isinstance(nav["hardwareConcurrency"], int)


def test_stealth_webgl_fields():
    """Verify WebGL fingerprint spoofing fields exist."""
    path = Path("fp_sentinel/browser/profiles/stealth.json")
    data = json.loads(path.read_text())
    webgl = data["webgl"]
    assert "vendor" in webgl
    assert "renderer" in webgl
    assert len(webgl["vendor"]) > 0


def test_stealth_screen_fields():
    """Verify screen resolution configuration."""
    path = Path("fp_sentinel/browser/profiles/stealth.json")
    data = json.loads(path.read_text())
    screen = data["screen"]
    assert screen["width"] == 1920
    assert screen["height"] == 1080
    assert screen["colorDepth"] == 24


def test_stealth_canvas_noise():
    """Verify canvas noise configuration."""
    path = Path("fp_sentinel/browser/profiles/stealth.json")
    data = json.loads(path.read_text())
    canvas = data["canvas"]
    assert "noise_seed" in canvas
    assert "method" in canvas


def test_stealth_fonts_list():
    """Verify fonts list is non-empty."""
    path = Path("fp_sentinel/browser/profiles/stealth.json")
    data = json.loads(path.read_text())
    assert isinstance(data["fonts"], list)
    assert len(data["fonts"]) >= 5
    assert "Arial" in data["fonts"]
