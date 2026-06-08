import sys
import json
import subprocess
import scanner
import plugin_loader
import ai_analyzer
import chromadb
from web_discovery import run_nikto, discover_paths

chroma_client = chromadb.PersistentClient(path="./cve_db")
col = chroma_client.get_or_create_collection("cve_database")

def query_rag(service, version):
    query = f"{service} {version} vulnerability exploit"
    print(f"  [RAG] Query: '{query}'")
    results = col.query(query_texts=[query], n_results=2)
    matches = results["metadatas"][0] if results["ids"][0] else []
    for m in matches:
        print(f"  [RAG] Match: {m['id']} | {m['service']} | CVSS {m['cvss']}")
    return matches

def main():
    target_ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"

    print("\n" + "="*60)
    print(f"  AI VAPT PIPELINE - TARGET: {target_ip}")
    print("="*60)

    # TẦNG 1: Nmap
    print("\n[TẦNG 1] NETWORK SCAN: Nmap")
    print(f"  Lệnh: nmap -p 21,80,8080 -sV {target_ip}")
    raw = subprocess.run(['nmap', '-p', '21,80,8080', '-sV', target_ip], capture_output=True, text=True)
    print("\n  [RAW NMAP OUTPUT]:")
    for line in raw.stdout.split('\n'):
        print(f"    {line}")

    scan_results = scanner.run_scan(target_ip)
    print(f"\n  [PARSED - sau cắt tỉa]:")
    print("  " + json.dumps(scan_results, indent=4).replace('\n', '\n  '))

    plugins = plugin_loader.load_all_plugins()
    shared_context = {}

    for port_info in scan_results:
        print(f"\n{'─'*60}")
        print(f"  Port {port_info['port']} | {port_info['service']} | {port_info['version']}")

        # RAG lookup
        print(f"\n  [RAG LOOKUP]:")
        rag_matches = query_rag(port_info['service'], port_info['version'])

        # TẦNG 2: Web Discovery (chỉ khi là HTTP)
        web_endpoints = []
        if port_info['service'] in ['http', 'https']:
            print(f"\n[TẦNG 2] WEB DISCOVERY:")

            # Auth trước để lấy session
            for plugin in plugins:
                if plugin.METADATA.get('id') == 'AGENT-001':
                    result = plugin.verify(target_ip, port_info['port'], context=shared_context)
                    if 'session_cookie' in shared_context:
                        print(f"  [Session] {shared_context['session_cookie']}")
                    break

            # Nikto scan
            print(f"\n  [Nikto Header Analysis]:")
            nikto_findings = run_nikto(target_ip, port_info['port'])

            # Web path discovery
            print(f"\n  [Path Discovery]:")
            if shared_context.get('session_cookie'):
                web_endpoints = discover_paths(
                    target_ip,
                    shared_context['session_cookie'],
                    port_info['port']
                )
                shared_context['web_endpoints'] = web_endpoints

        # TẦNG 3: Plugin + Verify
        print(f"\n[TẦNG 3] PLUGIN SCAN & VERIFY:")
        for plugin in plugins:
            if plugin.METADATA.get('id') == 'AGENT-001':
                continue  # đã chạy ở tầng 2
            if not plugin.match(port_info):
                continue

            print(f"\n  ✓ Plugin: {plugin.METADATA['name']} [{plugin.METADATA['id']}]")

            print(f"\n  [BƯỚC 4] SELF-VALIDATION:")
            result = plugin.verify(target_ip, port_info['port'], context=shared_context)

            print(f"\n  [BƯỚC 5] CONFIRMATION:")
            print(f"    Status  : {result['status']}")

            print(f"\n  [BƯỚC 6] EVIDENCE:")
            print(f"    {result['evidence']}")

            if result['status'] == 'CONFIRMED':
                import os, datetime
                os.makedirs("evidence", exist_ok=True)
                fname = f"evidence/{plugin.METADATA['id']}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                with open(fname, 'w') as f:
                    f.write(f"Target: {target_ip}:{port_info['port']}\n")
                    f.write(f"Plugin: {plugin.METADATA['name']}\n")
                    f.write(f"CVE: {plugin.METADATA['id']}\n")
                    f.write(f"CVSS: {plugin.METADATA.get('cvss_score','N/A')}\n")
                    f.write(f"Web endpoints found: {json.dumps(web_endpoints, ensure_ascii=False)}\n")
                    f.write(f"RAG matches: {json.dumps(rag_matches, ensure_ascii=False)}\n")
                    f.write(f"Evidence:\n{result['evidence']}\n")
                print(f"    [FILE] Evidence: {fname}")

                print(f"\n  [BƯỚC 7] AI ANALYSIS:")
                ai_report = ai_analyzer.analyze_finding(plugin.METADATA, result)
                print("  " + json.dumps(ai_report, indent=4, ensure_ascii=False).replace('\n', '\n  '))

            tier = {
                "CONFIRMED":     "🔴 Confirmed Vulnerability",
                "FALSE_POSITIVE":"⚪ False Positive",
                "PENDING":       "🟡 Potential Issue",
                "INFORMATIONAL": "🔵 Informational Finding"
            }.get(result['status'], result['status'])

            print(f"\n  [BƯỚC 8] REPORT: {tier}")
            print(f"    CVE: {plugin.METADATA['id']} | CVSS: {plugin.METADATA.get('cvss_score','N/A')}")
            print("  " + "─"*50)

    print("\n" + "="*60)
    print("  PIPELINE HOÀN TẤT")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
