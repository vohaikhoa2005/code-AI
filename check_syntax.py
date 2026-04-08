try:
    with open('app.py', 'r', encoding='utf-8') as f:
        content = f.read()
    compile(content, 'app.py', 'exec')
    print('Syntax is correct')
except SyntaxError as e:
    print(f'Syntax error at line {e.lineno}: {e.text}')
    print(f'Error: {e.msg}')