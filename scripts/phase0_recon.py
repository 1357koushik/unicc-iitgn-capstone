import sqlite3
import json
import os

print("--- SQLITE SCHEMA CHECK ---")
conn = sqlite3.connect('data/sqlite/corpus_store.db')
cursor = conn.cursor()
cursor.execute("SELECT sql FROM sqlite_master WHERE type='table';")
for row in cursor.fetchall():
    print(row[0])
    print("-" * 50)

cursor.execute("SELECT sql FROM sqlite_master WHERE type='index';")
print("--- INDICES ---")
for row in cursor.fetchall():
    print(row[0])

cursor.execute("SELECT count(*) FROM corpus;")
print(f"Total chunks: {cursor.fetchone()[0]:,}")

cursor.execute("SELECT * FROM corpus LIMIT 1;")
cols = [d[0] for d in cursor.description]
sample = cursor.fetchone()
print("\n--- SAMPLE CHUNK RECORD ---")
for col, val in zip(cols, sample):
    s = str(val)
    if len(s) > 150:
        s = s[:150] + "..."
    print(f"  {col}: {s}")

print("\n--- CHECKING DOC_ID FORMAT ---")
cursor.execute("SELECT doc_id, count(*) FROM corpus GROUP BY doc_id LIMIT 10;")
for row in cursor.fetchall():
    print(f"  doc_id='{row[0]}': count={row[1]}")

cursor.execute("SELECT doc_id FROM corpus WHERE doc_id LIKE 'CVE-%' LIMIT 5;")
print("Sample CVE doc_ids:", cursor.fetchall())
