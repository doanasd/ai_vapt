import sys
import json
import subprocess
import scanner
import plugin_loader
import ai_analyzer
import chromadb

# Init RAG
chroma_client = chromadb.PersistentClient(path="./cve_db")
col = chroma_client.get_or_create_collection("cve_database")

def query_rag(service, version):
    query = f"{service} {version} vulnerability exploit"
    print(f"  [RAG] Query: '{query}'")
    results = col.query(query_texts=[query], n_results=2)
    matches = results["metadatas"][0] if results["ids"][0] else []
    if matches:
        for m in matches:
            print(f"  [RAG] Match: {m['id']} | {m['service']} | CVSS {m['cvss']}")
    else:
        print(f"  [RAG] Không tìm thấy CVE phù hợp trong database")
    return matches

def main():
    target_ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"

    print("\n" + "="*60)
    print(f"  AI VAPT PIPELINE - TARGET: {target_ip}")
    print("="*60)

    # BƯỚC 1: Raw Nmap
    print("\n[BƯỚC 1] TECHNIQUE: Nmap Service Version Detection")
    print(f"  Lệnh: nmap -p 21,80,8080 -sV {target_ip}")
    raw = subprocess.run(['nmap', '-p', '21,80,8080', '-sV', target_ip], capture_output=True, text=True)
    print("\n  [RAW NMAP OUTPUT]:")
    for line in raw.stdout.split('\n'):
        print(f"    {line}")

    # BƯỚC 2: Parse + Context Optimization
    print("\n[BƯỚC 2] TOOL OUTPUT + CONTEXT OPTIMIZATION:")
    print("  Parser: bỏ closed/filtered, chỉ giữ OPEN")
    scan_results = scanner.run_scan(target_ip)
    print(f"\n  [PARSED - sau cắt tỉa]:")
    print("  " + json.dumps(scan_results, indent=4, ensure_ascii=False).replace('\n', '\n  '))

    # BƯỚC 3: Plugin load + RAG
    print("\n[BƯỚC 3] AI ANALYSIS:")
    plugins = plugin_loader.load_all_plugins()
    print(f"  Plugins nạp: {[p.METADATA['name'] for p in plugins]}")

    shared_context = {}

    for port_info in scan_results:
        print(f"\n{'─'*60}")
        print(f"  Phân tích: port {port_info['port']} | {port_info['service']} | {port_info['version']}")

        # RAG lookup
        print(f"\n  [RAG LOOKUP]:")
        rag_matches = query_rag(port_info['service'], port_info['version'])

        for plugin in plugins:
            if not plugin.match(port_info):
                continue

            is_agent = plugin.METADATA.get('cvss_score', 0) == 0.0
            label = "🔧 Internal Agent" if is_agent else f"CVE: {plugin.METADATA['id']}"

            print(f"\n  ✓ MATCH: {plugin.METADATA['name']} [{label}]")

            # BƯỚC 4: Self-validation
            print(f"\n[BƯỚC 4] AI SELF-VALIDATION: {plugin.METADATA['name']}")
            result = plugin.verify(target_ip, port_info['port'], context=shared_context)

            if 'session_cookie' in shared_context:
                print(f"  [CONTEXT] shared_context['session_cookie'] = {shared_context['session_cookie']}")

            # BƯỚC 5: Confirmation
            print(f"\n[BƯỚC 5] CONFIRMATION CONDITION:")
            print(f"  Status  : {result['status']}")

            # BƯỚC 6: Evidence (đổi tên từ PROMPT)
            print(f"\n[BƯỚC 6] EVIDENCE:")
            print(f"  {result['evidence']}")

            # Ghi file evidence nếu CONFIRMED
            if result['status'] == 'CONFIRMED':
                import os, datetime
                os.makedirs("evidence", exist_ok=True)
                fname = f"evidence/{port_info['service']}_{plugin.METADATA['id']}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                with open(fname, 'w') as f:
                    f.write(f"Target: {target_ip}:{port_info['port']}\n")
                    f.write(f"Plugin: {plugin.METADATA['name']}\n")
                    f.write(f"CVE: {plugin.METADATA['id']}\n")
                    f.write(f"CVSS: {plugin.METADATA.get('cvss_score','N/A')}\n")
                    f.write(f"RAG matches: {json.dumps(rag_matches, ensure_ascii=False)}\n")
                    f.write(f"Evidence:\n{result['evidence']}\n")
                print(f"  [FILE] Evidence ghi ra: {fname}")

                # AI Analysis
                print(f"\n  [AI] Gửi evidence cho Groq phân tích...")
                ai_report = ai_analyzer.analyze_finding(plugin.METADATA, result)
                print(f"  [AI RESPONSE]:")
                print("  " + json.dumps(ai_report, indent=4, ensure_ascii=False).replace('\n', '\n  '))

            # BƯỚC 7: Report
            tier = {
                "CONFIRMED":     "🔴 Confirmed Vulnerability",
                "FALSE_POSITIVE":"⚪ False Positive",
                "PENDING":       "🟡 Potential Issue",
                "INFORMATIONAL": "🔵 Informational Finding"
            }.get(result['status'], result['status'])

            print(f"\n[BƯỚC 7] REPORT OUTPUT:")
            if is_agent:
                print(f"  Type    : 🔧 Internal Agent (không phải CVE)")
            else:
                print(f"  CVE     : {plugin.METADATA['id']} | CVSS: {plugin.METADATA.get('cvss_score','N/A')}")
            print(f"  Class   : {tier}")
            print(f"  Target  : {target_ip}:{port_info['port']}")
            print("  " + "─"*50)

    print("\n" + "="*60)
    print("  PIPELINE HOÀN TẤT")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
