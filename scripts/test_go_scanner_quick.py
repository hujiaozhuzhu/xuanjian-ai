"""Go Scanner 快速功能测试"""
import asyncio
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fp_sentinel.models import ScanTool
from fp_sentinel.rules.go import GO_SECURITY_RULES, GO_RULES_INDEX, GO_SECURITY_GUARD_PATTERNS
from fp_sentinel.scanners.go_scanner import GoScanner
from fp_sentinel.scanners.manager import ScannerManager


def main():
    print("=== 模块导入验证 ===")
    print(f"ScanTool.GO_SCANNER = {ScanTool.GO_SCANNER.value}")
    print(f"GO_SECURITY_RULES: {len(GO_SECURITY_RULES)} 条")
    print(f"GO_SECURITY_GUARD_PATTERNS: {len(GO_SECURITY_GUARD_PATTERNS)} 组")

    # 验证 GoScanner 初始化
    scanner = GoScanner(config={"check_hardcoded_secrets": True})
    print(f"GoScanner 类型: {scanner.get_tool_type().value}")

    # 靶场代码测试
    target = tempfile.mkdtemp()
    go_file = os.path.join(target, "vuln.go")
    with open(go_file, "w") as f:
        f.write(
            'package main\n'
            'import (\n'
            '    "fmt"\n'
            '    "os/exec"\n'
            '    "database/sql"\n'
            '    _ "github.com/go-sql-driver/mysql"\n'
            ')\n'
            'var apiKey = "AKIAIOSFODNN7EXAMPLE"\n'
            'var secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
            'func query(userID string) {\n'
            '    db, _ := sql.Open("mysql", "root:password@/testdb")\n'
            '    query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)\n'
            '    db.Query(query)\n'
            '}\n'
            'func run(cmd string) {\n'
            '    exec.Command("sh", "-c", cmd).Run()\n'
            '}\n'
        )

    results = asyncio.run(scanner.scan(go_file))
    print(f"\n=== Go 靶场扫描测试 ===")
    print(f"发现漏洞: {len(results)} 条")
    for r in results:
        print(f"  [{r.severity.value}] {r.rule_id}: line {r.line}")

    # 误报抑制测试（_test.go）
    target2 = tempfile.mkdtemp()
    test_file = os.path.join(target2, "example_test.go")
    with open(test_file, "w") as f:
        f.write(
            'package main\n'
            'var password = "test"\n'
            'func TestExample(t *testing.T) {}\n'
        )
    scanner2 = GoScanner(config={"check_hardcoded_secrets": True})
    results_fp = asyncio.run(scanner2.scan(test_file))
    print(f"\n=== Go 误报抑制测试（example_test.go） ===")
    print(f"发现漏洞: {len(results_fp)} 条 (应为 0)")

    # 验证 ScannerManager 支持 Go
    print(f"\n=== ScannerManager 验证 ===")
    manager = ScannerManager()
    go_scanners = manager._select_scanners("go")
    print(f"Go 语言选择扫描器: {[s.value for s in go_scanners]}")
    assert ScanTool.GO_SCANNER in go_scanners, "GoScanner 应在 Go 语言扫描器列表中"

    # 语言自动检测
    target3 = tempfile.mkdtemp()
    go_mod = os.path.join(target3, "go.mod")
    with open(go_mod, "w") as f:
        f.write("module example.com/test\n\ngo 1.21\n")
    detected = manager._detect_language(target3)
    print(f"go.mod 检测语言: {detected}")
    assert detected == "go", f"期望go 实际{detected}"

    # .go 单文件检测
    target4 = tempfile.mkdtemp()
    single_go = os.path.join(target4, "main.go")
    with open(single_go, "w") as f:
        f.write("package main\nfunc main() {}\n")
    detected2 = manager._detect_language(single_go)
    print(f"main.go 单文件检测: {detected2}")
    assert detected2 == "go"

    print("\n=== 全部验证通过 ===")


if __name__ == "__main__":
    main()
