import os
import json
from scanner import run_nmap
from ai_analyzer import ai_analyze
from verify.reactor import run_verify
from report.generator import generate_report

with open("rules/validation_rules.json") as f:
    RULES = json.load(f)["rules"]

import chromadb
chroma_client = chromadb.PersistentClient(path="./cve_db")
col = chroma_client.get_or_create_collection("cve_database")

def query_rag(service, version):
    results = col.query(
        query_texts=[f"{service} {version} vulnerability exploit"],
        n_results=2
    )
    return results["metadatas"][0] if results["ids"][0] else []

def match_rule(service, version):
    for rule in RULES:
        m = rule["match"]
        svc_ok = m.get("service","") in service
        ver_ok = (m.get("version","") in version) if m.get("version") else True
        if svc_ok and ver_ok:
            return rule
    return None

def run_pipeline(target_ip):
    print(f"\n{'='*50}")
    print(f"[*] Bắt đầu AI VAPT pipeline: {target_ip}")
    print(f"{'='*50}")

    findings = run_nmap(target_ip)
    print(f"[*] Tìm được {len(findings)} port open")

    for finding in findings:
        print(f"\n[→] Port {finding['port']} | {finding['service']} {finding['version']}")

        # Bước 3: RAG
        cve_candidates = query_rag(finding["service"], finding["version"])
        print(f"[*] RAG: {len(cve_candidates)} CVE candidates")

        # Bước 3: AI phân tích
        try:
            ai_result = ai_analyze(finding, cve_candidates)
            print(f"[*] AI: {ai_result.get('cve_match')} | confidence={ai_result.get('confidence')} | severity={ai_result.get('severity')}")
        except Exception as e:
            print(f"[WARN] AI lỗi: {e}")
            ai_result = {"error": str(e)}

        # Bước 4-5: Rule + Verify
        rule = match_rule(finding["service"], finding["version"])
        if rule:
            print(f"[*] Rule: {rule['name']} → {rule['verify_method']}")
            verify_result = run_verify(rule["verify_method"], target_ip)
        else:
            verify_result = {"status": "INFORMATIONAL", "severity": "Informational"}

        print(f"[*] Verify: {verify_result['status']}")

        # Bước 6-7: Report
        generate_report(target_ip, finding, ai_result, verify_result)

    print(f"\n[✓] Pipeline hoàn tất")

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    run_pipeline(target)
