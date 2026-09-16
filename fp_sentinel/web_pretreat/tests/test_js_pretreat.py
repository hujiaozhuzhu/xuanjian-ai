"""js_pretreat 模块的单元测试。

覆盖功能:
- prettify: jsbeautifier 原生路径 + 正则降级路径
- extract_strings: URL/api_path/secret_like/comment_like 标签
- find_api_patterns: URL/fetch/axios 匹配 + 行号
- find_suspicious: eval/Function/document.write/innerHTML/atob
- detect_packer: eval_packed/url_encoded/webpack/obfuscator-io
- 大文件 >5MB 自动分块 warning

测试数据为人工构造的最小 JS 样本。
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from fp_sentinel.web_pretreat import js_pretreat as jp_mod
from fp_sentinel.web_pretreat.js_pretreat import JsPrettier, _regex_prettify


def _build_sample_js() -> str:
    """构建含 eval/XSS/密钥/拼接 的最小 JS 样本（避免 E501 长行）。"""
    parts = [
        "(function(){",
        'var token="sk-abc123def456secret789";',
        'var api_url="/api/v1/users";',
        'var b="https://example.com/endpoint";',
        "eval(\"console.log('dynamic code')\");",
        'document.write("<s"+"cript>alert(1)</s"+"cript>");',
        "document.getElementById('x').innerHTML=user_input;",
        "fetch(api_url);})();",
    ]
    return "".join(parts)


SAMPLE_JS: str = _build_sample_js()

SAMPLE_WITH_CHINESE: str = (
    "// \u6d4b\u8bd5\u6570\u636e\n"
    'var api_key="key_xxx_123_secret_abc";\n'
    "// \u751f\u4ea7 token \u4e0d\u8981\u5728\u524d\u7aef"
)

SAMPLE_WEBPACK: str = (
    "webpackJsonp([0],[function(e,t)"
    "{console.log('packed')}],[[0,1]])"
)

SAMPLE_OBFUSCATED: str = (
    "var _0x1a2b=['hello','atob'];"
    "(function(_0x1a2b3c,_0x4d5e6f){})(_0x1a2b,0x1);"
)

SAMPLE_URL_ENCODED: str = (
    "unescape('%3Cscript%3Ealert(1)%3C/script%3E')"
)

SAMPLE_FENG: str = "String.fromCharCode(72,101,108,108,111)"


# ──────────────────────────────────────────────────────
# prettify
# ──────────────────────────────────────────────────────


class TestPrettify:
    """JsPrettier.prettify 的测试。"""

    def test_prettify_with_fallback(self) -> None:
        """未安装 jsbeautifier 时：正则降级路径应产出多行输出。"""
        prettier = JsPrettier()
        with patch.object(jp_mod, "jsbeautifier", None):
            out = prettier.prettify(SAMPLE_JS)

        # 美化后必须包含换行
        assert "\n" in out
        # 原始关键字保留
        assert "eval" in out
        assert "document.write" in out

    def test_prettify_with_beautifier(self) -> None:
        """jsbeautifier 可用时，源码应经过美化。"""
        fake_beautifier = MagicMock()
        fake_beautifier.beautify.return_value = "/* beautified */\neval('x');\n"
        prettier = JsPrettier()

        with patch.object(jp_mod, "jsbeautifier", fake_beautifier):
            out = prettier.prettify(SAMPLE_JS)

        assert out == "/* beautified */\neval('x');\n"
        fake_beautifier.beautify.assert_called_once()

    def test_prettify_empty_input(self) -> None:
        """空输入应原样返回。"""
        prettier = JsPrettier()
        assert prettier.prettify("") == ""

    def test_has_beautifier_flag(self) -> None:
        """has_beautifier 应正确反映依赖是否加载。"""
        prettier = JsPrettier()
        assert prettier.has_beautifier == (jp_mod.jsbeautifier is not None)


# ──────────────────────────────────────────────────────
# _regex_prettify
# ──────────────────────────────────────────────────────


class TestRegexPrettify:
    """_regex_prettify 的独立测试。"""

    def test_basic_newlines(self) -> None:
        out = _regex_prettify("a=1;b=2;c=3;")
        assert "a=1;" in out
        assert "b=2;" in out
        assert "\n" in out

    def test_preserves_strings(self) -> None:
        """字符串内部的分号不应导致断行。"""
        src = 'x="he;llo";y=\'a;b\';'
        out = _regex_prettify(src)
        assert '"he;llo"' in out
        assert "'a;b'" in out

    def test_preserves_line_comments(self) -> None:
        """行内注释内的分号不应导致断行。"""
        src = "// a;b;c\nvar x=1;"
        out = _regex_prettify(src)
        assert "a;b;c" in out

    def test_preserves_block_comments(self) -> None:
        """块注释内的分号不应导致断行。"""
        src = "/* a;b;c */var x=1;"
        out = _regex_prettify(src)
        assert "a;b;c" in out


# ──────────────────────────────────────────────────────
# extract_strings
# ──────────────────────────────────────────────────────


class TestExtractStrings:
    """extract_strings 测试集。"""

    def test_url_tagged(self) -> None:
        """https 开头的字面量应标为 url。"""
        prettier = JsPrettier(min_string_len=3)
        strings = prettier.extract_strings(SAMPLE_JS)
        urls = [s for s in strings if s["tag"] == "url"]
        assert any("example.com" in s["value"] for s in urls)

    def test_api_path_tagged(self) -> None:
        """以 /api 开头的字面量应标为 api_path。"""
        prettier = JsPrettier(min_string_len=3)
        strings = prettier.extract_strings(SAMPLE_JS)
        api_items = [s for s in strings if s["tag"] == "api_path"]
        assert any("/api/v1/users" == s["value"] for s in api_items)

    def test_secret_like_tagged(self) -> None:
        """含 secret/token/key 的长字面量应标为 secret_like。"""
        prettier = JsPrettier(min_string_len=3)
        strings = prettier.extract_strings(SAMPLE_JS)
        secrets = [s for s in strings if s["tag"] == "secret_like"]
        assert any(
            "sk-" in s["value"] or "secret" in s["value"] for s in secrets
        )

    def test_chinese_comment_no_crash(self) -> None:
        """含 CJK 的源码不应导致 extract_strings 抛异常。"""
        prettier = JsPrettier(min_string_len=3)
        src_str = "// \u8fd9\u662f\u6d4b\u8bd5\u6570\u636e"
        strings = prettier.extract_strings(src_str)
        assert isinstance(strings, list)

    def test_min_len_filters_short_strings(self) -> None:
        """过短的噪音串应被过滤。"""
        src = 'a="ab";b="abcdef";'
        prettier = JsPrettier(min_string_len=4)
        strings = prettier.extract_strings(src)
        values = [s["value"] for s in strings]
        assert "ab" not in values
        assert "abcdef" in values

    def test_empty_input(self) -> None:
        prettier = JsPrettier()
        assert prettier.extract_strings("") == []


# ──────────────────────────────────────────────────────
# find_api_patterns
# ──────────────────────────────────────────────────────


class TestFindApiPatterns:
    """find_api_patterns 测试集。"""

    def test_http_url_matched(self) -> None:
        src = 'fetch("https://example.com/api/v1/data");'
        prettier = JsPrettier()
        apis = prettier.find_api_patterns(src)
        url_items = [a for a in apis if a["pattern_type"] == "url_http"]
        assert len(url_items) >= 1
        assert "example.com" in url_items[0]["match"]

    def test_fetch_pattern_matched(self) -> None:
        src = "fetch('/api/v2/users');"
        prettier = JsPrettier()
        apis = prettier.find_api_patterns(src)
        fetches = [a for a in apis if a["pattern_type"] == "fetch_api"]
        assert len(fetches) >= 1

    def test_line_number_report(self) -> None:
        """应正确报告行号。"""
        src = 'var a="https://example.com";\nfetch("https://other.com");'
        prettier = JsPrettier()
        apis = prettier.find_api_patterns(src)
        assert all("line" in a for a in apis)
        assert int(apis[0]["line"]) >= 1

    def test_line_number_second_line(self) -> None:
        """fetch 在第二行，line 字段应反映这一点。"""
        src = 'var a="https://example.com";\nfetch("https://other.com");'
        prettier = JsPrettier()
        apis = prettier.find_api_patterns(src)
        second = [a for a in apis if "other.com" in a["match"]]
        assert second and int(second[0]["line"]) == 2

    def test_empty_returns_empty(self) -> None:
        prettier = JsPrettier()
        assert prettier.find_api_patterns("") == []


# ──────────────────────────────────────────────────────
# find_suspicious
# ──────────────────────────────────────────────────────


class TestFindSuspicious:
    """find_suspicious 测试集。"""

    def test_eval_detected(self) -> None:
        src = "eval('code');"
        prettier = JsPrettier()
        sus = prettier.find_suspicious(src)
        types = [s["pattern_type"] for s in sus]
        assert "eval_function" in types

    def test_document_write_detected(self) -> None:
        src = "document.write('<div>unsafe</div>');"
        prettier = JsPrettier()
        sus = prettier.find_suspicious(src)
        types = [s["pattern_type"] for s in sus]
        assert "document_write" in types

    def test_innerhtml_detected(self) -> None:
        src = "el.innerHTML=user_input;"
        prettier = JsPrettier()
        sus = prettier.find_suspicious(src)
        types = [s["pattern_type"] for s in sus]
        assert "inner_html_assign" in types

    def test_atob_detected(self) -> None:
        src = "atob('SGVsbG8=');"
        prettier = JsPrettier()
        sus = prettier.find_suspicious(src)
        types = [s["pattern_type"] for s in sus]
        assert "atob_decode" in types

    def test_function_constructor_detected(self) -> None:
        src = "new Function('return 1')();"
        prettier = JsPrettier()
        sus = prettier.find_suspicious(src)
        types = [s["pattern_type"] for s in sus]
        assert "function_constructor" in types

    def test_all_carry_line_info(self) -> None:
        src = "var a='x';\neval('y');\n"
        prettier = JsPrettier()
        sus = prettier.find_suspicious(src)
        assert all("line" in s for s in sus)

    def test_eval_line_number_is_two(self) -> None:
        """eval 在第 2 行。"""
        src = "var a='x';\neval('y');\n"
        prettier = JsPrettier()
        sus = prettier.find_suspicious(src)
        eval_items = [s for s in sus if s["pattern_type"] == "eval_function"]
        assert eval_items and int(eval_items[0]["line"]) == 2

    def test_empty_returns_empty(self) -> None:
        prettier = JsPrettier()
        assert prettier.find_suspicious("") == []


# ──────────────────────────────────────────────────────
# detect_packer
# ──────────────────────────────────────────────────────


class TestDetectPacker:
    """detect_packer 测试集。"""

    def test_eval_packed(self) -> None:
        src = "eval(function(p,a,c,k,e,d){e=String;...})"
        prettier = JsPrettier()
        assert prettier.detect_packer(src) == "eval_packed"

    def test_url_encoded(self) -> None:
        src = "unescape('%3C%68%74%6D%6C%3E%74%65%73%74%3C%2'"
        "F%68%74%6D%6C%3E')"
        prettier = JsPrettier()
        assert prettier.detect_packer(src) == "url_encoded"

    def test_packer_feng(self) -> None:
        prettier = JsPrettier()
        assert prettier.detect_packer(SAMPLE_FENG) == "packer_feng"

    def test_webpack(self) -> None:
        prettier = JsPrettier()
        assert prettier.detect_packer(SAMPLE_WEBPACK) == "webpack"

    def test_obfuscator_io(self) -> None:
        prettier = JsPrettier()
        assert prettier.detect_packer(SAMPLE_OBFUSCATED) == "obfuscator_io"

    def test_none(self) -> None:
        src = "var a=1;\nfunction b(){return 2;}\n"
        prettier = JsPrettier()
        assert prettier.detect_packer(src) == "none"

    def test_empty_input(self) -> None:
        prettier = JsPrettier()
        assert prettier.detect_packer("") == "none"


# ──────────────────────────────────────────────────────
# 完整流水线 process()
# ──────────────────────────────────────────────────────


class TestFullPipeline:
    """JsPrettier.process 集成测试。"""

    def test_memory_warning_for_large_files(self) -> None:
        """超过 5MB 的文件应自动设置 memory_warning。"""
        big = "x" * (jp_mod.LARGE_FILE_THRESHOLD + 1024)
        prettier = JsPrettier()
        result = prettier.process(big)

        msg_categories = [w.category for w in result.warnings]
        assert "memory_warning" in msg_categories

    def test_process_returns_full_result(self) -> None:
        """process 应完整跑完全部子模块。"""
        prettier = JsPrettier()
        result = prettier.process(SAMPLE_JS)

        assert len(result.strings) >= 1
        types = {s["pattern_type"] for s in result.suspicious}
        assert "eval_function" in types or "document_write" in types
        assert isinstance(result.packer_type, str)
        assert result.packer_type in {"none", "unknown"}

    def test_process_empty_input(self) -> None:
        prettier = JsPrettier()
        result = prettier.process("")
        assert result.packer_type == "none"
        assert result.strings == []
        assert result.suspicious == []

    def test_process_webpack_detects_packer(self) -> None:
        """webpack 样本的 packer_type 应对应 webpack。"""
        prettier = JsPrettier()
        result = prettier.process(SAMPLE_WEBPACK)
        assert result.packer_type == "webpack"

    def test_process_with_chinese(self) -> None:
        """中文注释的源码不抛异常。"""
        prettier = JsPrettier()
        result = prettier.process(SAMPLE_WITH_CHINESE)
        secrets = [s for s in result.strings if s["tag"] == "secret_like"]
        assert secrets
