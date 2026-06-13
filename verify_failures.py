"""Verify the root causes of each test failure"""
import re

print("=" * 60)
print("FAILURE 1: test_nosec_filtered")
print("=" * 60)
# The default file path from make_scan_result is:
# "src/main/java/com/example/UserService.java"
# This matches path whitelist pattern .*/examples?/.*
p = re.compile(r'.*/examples?/.*')
test_path = 'src/main/java/com/example/UserService.java'
print(f"Path: {test_path}")
print(f"Matches .*/examples?/.* : {bool(p.match(test_path))}")
print("=> Path whitelist matches BEFORE code_ignore check runs!")
print("=> Description is about path whitelist, not nosec")
print()

# Verify nosec match itself would work
code_pat = re.compile(r'#\s*nosec', re.IGNORECASE)
m = code_pat.search('query = "SELECT * FROM users"  # nosec')
print(f"Nosec pattern match: {m}")
desc = f'代码中存在忽略标记: {code_pat.pattern}'
print(f"If nosec was checked: {desc}")
print(f"Contains 'nosec': {'nosec' in desc.lower()}")
print()

print("=" * 60)
print("FAILURE 2: test_normal_code_passes")
print("=" * 60)
# Same root cause - the file path matches path whitelist
print("Same root cause as FAILURE 1:")
print(f"  Path '{test_path}' matches .*/examples?/.*")
print("  => Result is FALSE_POSITIVE instead of NEEDS_REVIEW")
print()

print("=" * 60)
print("FAILURE 3: test_historical_fingerprint")
print("=" * 60)
print("Python scoping bug: variable 'f' used before assignment")
print("In the statement:")
print("  f = RuleFilter({")
print("      'enabled': True,")
print("      'false_positive_fingerprints': [f._compute_fingerprint(sr)],  # <-- 'f' not yet defined")
print("  })")
print("Python treats 'f' as local because of the assignment,")
print("but it's referenced on the RHS before being assigned.")
print()

print("=" * 60)
print("FAILURE 4: test_dead_code_detection")
print("=" * 60)
# Dead code patterns in context_filter.py
dead_code_patterns = [
    r"if\s+False\s*:", r"if\s+0\s*:", r"if\s+false\s*;",
]
pat = re.compile(r"if\s+false\s*;", re.MULTILINE)
test_java = "if (false) {\n  dangerous();\n}"
print(f"Test input: 'if (false) {{\\n  dangerous();\\n}}'")
print(f"Pattern 'if\\s+false\\s*;' matches: {bool(pat.search(test_java))}")
# Test Python
pat2 = re.compile(r"if\s+False\s*:", re.MULTILINE)
test_py = "if False:\n    dangerous()"
print(f"Pattern 'if\\s+False\\s*:' matches 'if False:': {bool(pat2.search(test_py))}")
print()
print("=> Java 'if (false) {' doesn't match any dead code pattern")
print("   Missing pattern for Java-style dead code: if\\s*\\(\\s*false\\s*\\)")

print()
print("=" * 60)
print("FAILURE 5: test_full_pipeline_real_vuln")
print("=" * 60)
path2 = "src/main/java/com/example/UserDAO.java"
print(f"Path: {path2}")
print(f"Matches .*/examples?/.* : {bool(p.match(path2))}")
print("=> Same root cause as FAILURE 1 - path whitelist too broad")
print("=> Real vulnerability gets FALSE_POSITIVE from L1 path match")
