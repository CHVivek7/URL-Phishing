from pathlib import Path
s = Path('templates/index.html').read_text(encoding='utf-8', errors='replace')
if_count = s.count('{% if')
endif_count = s.count('{% endif %}')
print('if_count=', if_count)
print('endif_count=', endif_count)
lines = s.splitlines()
stack = []
for i,l in enumerate(lines,1):
    lstr = l.strip()
    if lstr.startswith('{% if') and 'endif' not in lstr:
        stack.append((i,lstr))
    if lstr == '{% endif %}':
        if stack:
            stack.pop()
        else:
            print('Extra endif at', i)

print('remaining stack (unclosed ifs):')
for item in stack:
    print(item)
