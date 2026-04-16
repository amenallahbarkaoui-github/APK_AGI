import re

with open('src/apk_agent/agent/tools_def.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Find all @tool functions
pattern = r'@tool\s*\ndef\s+(\w+)\([^)]*\)\s*->\s*str:\s*\n\s*"""(.*?)"""'
matches = list(re.finditer(pattern, content, re.DOTALL))

missing_returns = []
missing_when = []
short_docs = []

for m in matches:
    name = m.group(1)
    doc = m.group(2)
    line_no = content[:m.start()].count('\n') + 1

    has_returns = bool(re.search(r'Returns:', doc, re.IGNORECASE))
    has_when = bool(re.search(r'When.to.use', doc, re.IGNORECASE))

    lines = [l.strip() for l in doc.strip().split('\n') if l.strip()]

    if not has_returns:
        missing_returns.append((name, line_no))
    if not has_when:
        missing_when.append((name, line_no))
    if len(lines) < 3:
        short_docs.append((name, line_no, len(lines)))

print(f'Total @tool functions: {len(matches)}')
print(f'\n=== Missing Returns ({len(missing_returns)}) ===')
for name, ln in missing_returns:
    print(f'  {name} (line {ln})')
print(f'\n=== Missing When-to-use ({len(missing_when)}) ===')
for name, ln in missing_when:
    print(f'  {name} (line {ln})')
print(f'\n=== Short docs <3 lines ({len(short_docs)}) ===')
for name, ln, cnt in short_docs:
    print(f'  {name} (line {ln}, {cnt} lines)')
