import ast, sys
files = ['web/api/results.py', 'web/main.py']
for f in files:
    try:
        ast.parse(open(f, encoding='utf-8').read())
        print('OK', f)
    except SyntaxError as e:
        print('FAIL', f, e)
