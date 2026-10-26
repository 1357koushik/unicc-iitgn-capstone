import sqlite3
import json

conn = sqlite3.connect('data/sqlite/corpus_store.db')
cursor = conn.cursor()

print("--- SOURCE_ORG BREAKDOWN ---")
cursor.execute('SELECT source_org, count(*) FROM corpus GROUP BY source_org;')
for row in cursor.fetchall():
    print(f"  source_org='{row[0]}': {row[1]:,}")

cursor.execute('SELECT count(*) FROM corpus WHERE doc_id LIKE "CVE-%";')
print(f"Records where doc_id starts with CVE-: {cursor.fetchone()[0]:,}")

cursor.execute('SELECT count(*) FROM corpus WHERE doc_id NOT LIKE "CVE-%";')
print(f"Records where doc_id does NOT start with CVE-: {cursor.fetchone()[0]:,}")

cursor.execute('SELECT doc_id, doc_title, source_org FROM corpus WHERE doc_id NOT LIKE "CVE-%" LIMIT 10;')
print("\nSample Non-CVE documents:")
for row in cursor.fetchall():
    print(f"  doc_id='{row[0]}' | org='{row[1]}' | title='{row[2]}'")

print("\n--- SAMPLE CVE-2017-0144 IN CORPUS ---")
cursor.execute('SELECT chunk_id, doc_id, doc_title, source_org, entities_json FROM corpus WHERE doc_id LIKE "%CVE-2017-0144%" LIMIT 5;')
for row in cursor.fetchall():
    print(f"  chunk_id={row[0]} | doc_id={row[1]} | org={row[3]}")
    print(f"    title={row[2]}")
    print(f"    entities={row[4][:120]}...")
