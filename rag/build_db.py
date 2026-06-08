import chromadb
client = chromadb.PersistentClient(path="./cve_db")
col = client.get_or_create_collection("cve_database")

cve_data = [
    {
        "id": "CVE-2011-2523",
        "service": "vsftpd",
        "version": "2.3.4",
        "description": "vsftpd 2.3.4 backdoor via smiley face in username opens shell port 6200",
        "cvss": "10.0",
        "verify_method": "tcp_port_6200",
        "exploit_module": "exploit/unix/ftp/vsftpd_234_backdoor"
    },
    {
        "id": "CVE-2017-0144",
        "service": "microsoft-ds",
        "version": "",
        "description": "EternalBlue SMB Remote Code Execution Windows MS17-010",
        "cvss": "9.3",
        "verify_method": "nmap_smb_script",
        "exploit_module": "exploit/windows/smb/ms17_010_eternalblue"
    },
    {
        "id": "CVE-2014-6271",
        "service": "http",
        "version": "bash",
        "description": "Shellshock bash remote code execution via HTTP headers CGI",
        "cvss": "10.0",
        "verify_method": "http_header_inject",
        "exploit_module": "exploit/multi/http/apache_mod_cgi_bash_env_exec"
    }
]

for cve in cve_data:
    col.add(
        documents=[cve["description"]],
        metadatas=[cve],
        ids=[cve["id"]]
    )

print(f"[OK] Đã nạp {len(cve_data)} CVE vào database")

# Test query ngay
results = col.query(query_texts=["vsftpd 2.3.4 backdoor"], n_results=2)
print(f"[OK] Test query vsftpd: tìm được {len(results['ids'][0])} kết quả")
for meta in results["metadatas"][0]:
    print(f"  → {meta['id']} | {meta['service']} | CVSS {meta['cvss']}")
