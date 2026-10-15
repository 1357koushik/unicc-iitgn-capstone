import sqlite3

conn = sqlite3.connect('data/sqlite/corpus_store.db')
cursor = conn.cursor()

print("1. Exact doc_id = 'CVE-2017-0144':")
cursor.execute("SELECT chunk_id, doc_id, source_org, doc_title FROM corpus WHERE doc_id = 'CVE-2017-0144';")
for row in cursor.fetchall():
    print("  ", row)

print("\n2. Chunk_id = '80d012b2da2575e69d44b66f29fc49ba':")
cursor.execute("SELECT chunk_id, doc_id, source_org, doc_title FROM corpus WHERE chunk_id = '80d012b2da2575e69d44b66f29fc49ba';")
for row in cursor.fetchall():
    print("  ", row)

print("\n3. text LIKE '%CVE-2017-0144%':")
cursor.execute("SELECT chunk_id, doc_id, source_org FROM corpus WHERE text LIKE '%CVE-2017-0144%';")
rows = cursor.fetchall()
print("   Count:", len(rows))
for r in rows[:5]:
    print("  ", r)

print("\n4. entities_json LIKE '%CVE-2017-0144%':")
cursor.execute("SELECT chunk_id, doc_id, source_org FROM corpus WHERE entities_json LIKE '%CVE-2017-0144%';")
rows = cursor.fetchall()
print("   Count:", len(rows))
for r in rows[:5]:
    print("  ", r)
