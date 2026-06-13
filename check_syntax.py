import ast, sys

files = [
    'fp_sentinel/web/app.py',
    'fp_sentinel/web/__init__.py',
    'fp_sentinel/server.py',
]
for f in files:
    try:
        with open(f) as fh:
            ast.parse(fh.read())
        print(f'OK {f}')
    except SyntaxError as e:
        print(f'FAIL {f}: {e}')
        sys.exit(1)

print('All syntax checks passed.')
