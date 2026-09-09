"""Final fix - replace HTML-python hybrid patterns with valid Python."""
import os
import re

LT = chr(60)
GT = chr(62)

def fix_file(filepath):
    with open(filepath, 'rb') as f:
        content = f.read()
    original = content
    
    # Pattern 1: func: <span>_REDACTED</span> self._method -> func: <REDACTED> self._method
    pat1 = rb'(\w+):\s*' + LT.encode() + b'_REDACTED' + GT.encode() + rb'\s*(self\._\test_\w+)'
    repl1 = rb'\1: \2'
    content = re.sub(pat1, repl1, content)
    
    # Pattern 2: field: <span>_REDACTED</span> -> field: str
    pat2 = rb'(\w+):\s*' + LT.encode() + b'_REDACTED' + GT.encode() + rb'\s*='
    repl2 = rb'\1: str ='
    content = re.sub(pat2, repl2, content)
    
    if content != original:
        with open(filepath, 'wb') as f:
            f.write(content)
        print("Fixed " + filepath)

base = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fp_sentinel')
count = 0
for root, dirs, files in os.walk(base):
    for fname in files:
        if fname.endswith('.py'):
            fix_file(os.path.join(root, fname))
            count += 1

print(f"Processed {count} files")
