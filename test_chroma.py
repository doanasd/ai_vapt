import chromadb
client = chromadb.PersistentClient(path="./cve_db")
col = client.get_or_create_collection("cve_database")
print("[OK] ChromaDB hoạt động")
print(f"[OK] Collection: {col.name}")
