import os
import json

root = "."
json_files = []
for r, d, files in os.walk(root):
    if any(p in r for p in ['.git', 'qdrant_storage', '.pytest_cache', '__pycache__', 'node_modules']):
        continue
    for f in files:
        if f.endswith('.json'):
            path = os.path.join(r, f)
            json_files.append(path)

print(f"Found {len(json_files)} json files:")
for jf in json_files:
    size = os.path.getsize(jf)
    print(f"  {jf} ({size:,} bytes)")
