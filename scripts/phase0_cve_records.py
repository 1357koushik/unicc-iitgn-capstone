import sqlite3
import re

conn = sqlite3.connect('data/sqlite/corpus_store.db')
cursor = conn.cursor()

cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

cursor.execute('SELECT doc_id FROM corpus LIMIT 1000;')
cve_set = set()
for row in cursor.fetchall():
    m = cve_pattern.search(row[0])
    if m:
        cve_set.add(m.group(0).upper())

print(f"Sample 1000 docs extracted {len(cve_set)} unique base CVE IDs.")

# Check all CVE-2017-0144 records
cursor.execute('SELECT chunk_id, doc_id, source_org, doc_title FROM corpus WHERE doc_id LIKE "%CVE-2017-0144%";')
rows = cursor.fetchall()
print(f"\nAll CVE-2017-0144 records in corpus ({len(rows)}):")
for r in rows:
    print(f"  chunk_id={r[0]} | doc_id={r[1]} | org={r[2]} | title={r[3][:60]}")
