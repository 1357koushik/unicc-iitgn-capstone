import os
import re

PATTERNS = ["confidence_tier", "composite_score"]
SKIP_DIRS = {".git", ".pytest_cache", "qdrant_storage", "__pycache__", "sections"}

root_dir = "."
matches = []

for root, dirs, files in os.walk(root_dir):
    dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith('.')]
    for file in files:
        if file.endswith(('.py', '.js', '.html', '.ts')):
            path = os.path.join(root, file)
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_no, line in enumerate(f, 1):
                        for pat in PATTERNS:
                            if pat in line:
                                matches.append((path, line_no, pat, line.strip()))
            except Exception:
                pass

print(f"Total references found: {len(matches)}")
print("=" * 80)
for path, line_no, pat, text in matches:
    print(f"{path}:{line_no} [{pat}] -> {text[:100]}")
