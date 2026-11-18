import sqlite3
import json

conn = sqlite3.connect('data/sqlite/corpus_store.db')
cursor = conn.cursor()

cursor.execute("SELECT count(*) FROM corpus WHERE entities_json LIKE '%\"sha256\": [\"%';")
sha_count = cursor.fetchone()[0]

cursor.execute("SELECT count(*) FROM corpus WHERE entities_json LIKE '%\"md5\": [\"%';")
md5_count = cursor.fetchone()[0]

cursor.execute("SELECT count(*) FROM corpus WHERE entities_json LIKE '%\"ipv4\": [\"%';")
ip_count = cursor.fetchone()[0]

print(f"Corpus records with SHA256: {sha_count:,}")
print(f"Corpus records with MD5:    {md5_count:,}")
print(f"Corpus records with IPv4:   {ip_count:,}")
