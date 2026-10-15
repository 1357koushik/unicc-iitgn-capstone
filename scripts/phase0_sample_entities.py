import sqlite3
import json

conn = sqlite3.connect('data/sqlite/corpus_store.db')
cursor = conn.cursor()

cursor.execute('SELECT source_org, entities_json FROM corpus WHERE source_org = "CISA" LIMIT 2;')
for r in cursor.fetchall():
    print(f"CISA entities: {r[1]}")

cursor.execute('SELECT source_org, entities_json FROM corpus WHERE source_org = "NVD" LIMIT 2;')
for r in cursor.fetchall():
    print(f"NVD entities: {r[1]}")
