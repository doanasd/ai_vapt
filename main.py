import sys
import json
import subprocess
import datetime
import os
import scanner
import plugin_loader
import ai_analyzer
import chromadb
from web_discovery import run_nikto, discover_paths

chroma_client = chromadb.PersistentClient(path="./cve_db")
col = chroma_client.get_or_create_collection("cve_database")

# ── RULE-BASED VALIDATION ENGINE ──────────────────────────
VALIDATION_RULES = {
    "DVWA-CMDI": {
        "confirm_markers": ["uid=", "www-data", "root"],
        "false_positive_markers": ["invalid", "error", "not found"],
        "min_evidence_length": 10,
        "description": "RCE confirmed nếu output chứa uid/username từ lệnh id/whoami"
    },
    "DVWA-LFI": {
        "confirm_markers": ["root:x:0:0:", "daemon:", "bin:x:"],
        "false_positive_markers": ["not found", "failed", "permission denied"],
        "min_evidence_length": 20,
        "description": "LFI confirmed nếu /etc/passwd content xuất hiện trong response"
    },
    "DVWA-SQLI": {
        "confirm_markers": ["admin", "First name", "Surname"],
        "false_positive_markers": ["error in your SQL", "mysql_fetch"],
        "min_evidence_length": 5,
        "description": "SQLi confirmed nếu dump được multiple user records"
    },
    "DVWA-UPLOAD": {
        "confirm_markers": ["uid=", "www-data"],
        "false_positive_markers": ["not permitted", "invalid file"],
        "min_evidence_length": 5,
        "description": "Upload RCE confirmed nếu webshell execute được lệnh hệ thống"
    },
    "DVWA-XSS": {
        "confirm_markers": ["<script>", "alert(", "onerror="],
        "false_positive_markers": ["&lt;script&gt;", "&#60;"],
        "min_evidence_length": 5,
        "description": "XSS confirmed nếu payload xuất hiện unescaped trong HTML response"
    },
    "DVWA-WEAK-SESSION": {
        "confirm_markers": ["sequential", "+1"],
        "false_positive_markers": [],
        "min_evidence_length": 5,
        "description": "Weak session confirmed nếu ID tăng tuần tự đoán được"
    },
}

def rule_based_validate(plugin_id, verify_result):
    """
    Bước 5: Rule-based validation
    So khớp evidence với bộ rule định nghĩa sẵn
    Trả về: pass/fail + lý do cụ thể
    """
    rules = VALIDATION_RULES.get(plugin_id)
    evidence = verify_result.get("evidence", "")
    status = verify_result.get("status", "")

    if not rules:
        return {
            "validated": status == "CONFIRMED",
            "reason": "Không có rule cụ thể — dùng kết quả verify trực tiếp",
            "rule_applied": "NONE"
        }

    # Check false positive markers trước
    for marker in rules["false_positive_markers"]:
        if marker.lower() in evidence.lower():
            return {
                "validated": False,
                "reason": f"False positive marker phát hiện: '{marker}'",
                "rule_applied": rules["description"]
            }

    # Check confirm markers
    matched = [m for m in rules["confirm_markers"] if m.lower() in evidence.lower()]
    if matched and len(evidence) >= rules["min_evidence_length"]:
        return {
            "validated": True,
            "reason": f"Confirm markers khớp: {matched}",
            "rule_applied": rules["description"]
        }

    return {
        "validated": False,
        "reason": f"Không đủ evidence — cần markers: {rules['confirm_markers']}",
        "rule_applied": rules["description"]
    }

def query_rag(service, version):
    query = f"{service} {version} vulnerability exploit"
    print(f"    Query: '{query}'")
    results = col.query(query_texts=[query], n_results=2)
    matches = results["metadatas"][0] if results["ids"][0] else []
    for m in matches:
        print(f"    → {m['id']} | {m['service']} | CVSS {m['cvss']} | {m['description'][:60]}...")
    return matches

def generate_report(target_ip, port, plugin, verify_result, validation, ai_report, rag_matches):
    """Tạo báo cáo chi tiết chuẩn pentest"""
    now = datetime.datetime.now()
    tier_map = {
        "CONFIRMED":     ("CRITICAL" if plugin.METADATA.get('cvss_score',0) >= 9.0 else "HIGH" if plugin.METADATA.get('cvss_score',0) >= 7.0 else "MEDIUM"),
        "FALSE_POSITIVE": "FALSE_POSITIVE",
        "PENDING":        "POTENTIAL",
        "INFORMATIONAL":  "INFORMATIONAL"
    }
    severity = tier_map.get(verify_result['status'], "UNKNOWN")

    report = {
        "report_metadata": {
            "generated_at": now.isoformat(),
            "tool": "AI VAPT System v1.0",
            "pipeline": "7-step AI VAPT Pipeline"
        },
        "target": {
            "ip": target_ip,
            "port": port,
            "url": f"http://{target_ip}:{port}"
        },
        "finding": {
            "id": plugin.METADATA['id'],
            "name": plugin.METADATA['name'],
            "cvss_score": plugin.METADATA.get('cvss_score', 'N/A'),
            "severity": severity,
            "status": verify_result['status'],
            "classification": {
                "CONFIRMED":      "🔴 Confirmed Vulnerability",
                "FALSE_POSITIVE": "⚪ False Positive",
                "PENDING":        "🟡 Potential Issue",
                "INFORMATIONAL":  "🔵 Informational Finding"
            }.get(verify_result['status'])
        },
        "validation": {
            "rule_based_result": validation['validated'],
            "rule_applied": validation['rule_applied'],
            "validation_reason": validation['reason']
        },
        "evidence": verify_result['evidence'],
        "rag_references": [
            {"cve": m.get('id'), "cvss": m.get('cvss'), "description": m.get('description')}
            for m in rag_matches
        ],
        "ai_analysis": ai_report if ai_report else {},
        "reproduction_steps": [
            f"1. Truy cập target: http://{target_ip}:{port}",
            f"2. Authenticate với default credential (admin:password)",
            f"3. Điều hướng đến endpoint vulnerable",
            f"4. Gửi payload như trong evidence",
            f"5. Quan sát response chứa dữ liệu nhạy cảm"
        ],
        "references": {
            "owasp": f"https://owasp.org/www-project-top-ten/",
            "cve": f"https://nvd.nist.gov/vuln/search/results?query={plugin.METADATA['id']}"
        }
    }
    return report

def main():
    target_ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"

    print("\n" + "="*60)
    print(f"  AI VAPT PIPELINE - TARGET: {target_ip}")
    print(f"  Thời gian: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)

    	# BƯỚC 1: NETWORK RECONNAISSANCE ───────────────────────
    print("\n[TẦNG 1] NETWORK RECONNAISSANCE (Nmap -sV)")
    print(f"  Mục tiêu: phát hiện port mở, service, version")
    print(f"  Lệnh   : nmap -p 21,80,8080 -sV {target_ip}\n")
    raw = subprocess.run(['nmap', '-p', '21,80,8080', '-sV', target_ip], capture_output=True, text=True)
    for line in raw.stdout.split('\n'):
        print(f"  {line}")

    	# BƯỚC 2: CONTEXT OPTIMIZATION ─────────────────────────
    print("\n[TẦNG 2] CONTEXT OPTIMIZATION (Parser Agent)")
    print(f"  Mục tiêu: cắt tỉa log rác, chỉ giữ port OPEN")
    print(f"  Lý do  : giảm token nạp vào LLM, tránh context overflow\n")
    scan_results = scanner.run_scan(target_ip)
    print(f"  [PARSED OUTPUT]:")
    print("  " + json.dumps(scan_results, indent=4).replace('\n', '\n  '))

    	# BƯỚC 3: AI ANALYSIS + RAG ────────────────────────────
    print("\n[TẦNG 3] AI ANALYSIS + RAG LOOKUP")
    print(f"  Mục tiêu: AI tra cứu CVE database, tìm kịch bản tấn công phù hợp")
    plugins = plugin_loader.load_all_plugins()
    print(f"  Plugins đã nạp ({len(plugins)}):")
    for p in plugins:
        print(f"    → {p.METADATA['name']} [{p.METADATA['id']}] CVSS={p.METADATA.get('cvss_score','N/A')}")

    shared_context = {}
    all_reports = []

    for port_info in scan_results:
        print(f"\n{'─'*60}")
        print(f"  Phân tích: port {port_info['port']} | {port_info['service']} | {port_info['version']}")

        print(f"\n  [RAG LOOKUP] — AI tra CVE database:")
        rag_matches = query_rag(port_info['service'], port_info['version'])

        # Web Discovery
        web_endpoints = []
        if port_info['service'] in ['http', 'https']:
            print(f"\n  [WEB DISCOVERY] — Tìm endpoint vulnerable:")

            for plugin in plugins:
                if plugin.METADATA.get('id') == 'AGENT-001':
                    plugin.verify(target_ip, port_info['port'], context=shared_context)
                    if shared_context.get('session_cookie'):
                        print(f"  [Session] {shared_context['session_cookie']}")
                    break

            print(f"\n  [Nikto]:")
            run_nikto(target_ip, port_info['port'])

            print(f"\n  [Path Discovery]:")
            if shared_context.get('session_cookie'):
                web_endpoints = discover_paths(target_ip, shared_context['session_cookie'], port_info['port'])
                shared_context['web_endpoints'] = web_endpoints

        # ── PLUGIN SCAN ───────────────────────────────────────
        print(f"\n{'═'*60}")
        print(f"  PLUGIN SCAN & VERIFY")
        print(f"{'═'*60}")

        for plugin in plugins:
            if plugin.METADATA.get('id') == 'AGENT-001':
                continue
            if not plugin.match(port_info):
                continue

            meta = plugin.METADATA
            print(f"\n  ┌─ Plugin: {meta['name']} [{meta['id']}] CVSS={meta.get('cvss_score','N/A')}")

	# BƯỚC 4: AI SELF-VALIDATION
            print(f"  │")
            print(f"  ├─[BƯỚC 4] AI SELF-VALIDATION")
            print(f"  │  Mục tiêu: AI tự nghi ngờ, sinh payload, thử khai thác thực tế")
            print(f"  │  AI đang suy luận: 'Service là {port_info['service']}, endpoint có thể")
            print(f"  │  vulnerable với {meta['name']} — thử payload từ knowledge base...'")
            verify_result = plugin.verify(target_ip, port_info['port'], context=shared_context)

	# BƯỚC 5: RULE-BASED VALIDATION
            print(f"  │")
            print(f"  ├─[BƯỚC 5] RULE-BASED VALIDATION")
            validation = rule_based_validate(meta['id'], verify_result)
            print(f"  │  Rule áp dụng : {validation['rule_applied']}")
            print(f"  │  Kết quả      : {'✓ PASS' if validation['validated'] else '✗ FAIL'}")
            print(f"  │  Lý do        : {validation['reason']}")
            print(f"  │  Status       : {verify_result['status']}")

            # Override status nếu rule fail
            if not validation['validated'] and verify_result['status'] == 'CONFIRMED':
                verify_result['status'] = 'PENDING'
                print(f"  │  → Rule override: CONFIRMED → PENDING (chưa đủ evidence)")

	# BƯỚC 6: EVIDENCE
            print(f"  │")
            print(f"  ├─[BƯỚC 6] EVIDENCE")
            print(f"  │  {verify_result['evidence'].replace(chr(10), chr(10)+'  │  ')}")

            # Ghi file evidence
            if verify_result['status'] == 'CONFIRMED':
                os.makedirs("evidence", exist_ok=True)
                fname = f"evidence/{meta['id']}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                with open(fname, 'w') as f:
                    f.write(verify_result['evidence'])
                print(f"  │  [FILE] Ghi ra: {fname}")

	# BƯỚC 7: AI REPORT
            ai_report = None
            if verify_result['status'] == 'CONFIRMED':
                print(f"  │")
                print(f"  ├─[BƯỚC 7] AI DEEP ANALYSIS (Groq llama-3.3-70b)")
                ai_report = ai_analyzer.analyze_finding(meta, verify_result)
                print(f"  │  Vulnerability : {ai_report.get('vulnerability')}")
                print(f"  │  Impact        : {ai_report.get('impact')}")
                print(f"  │  Remediation   : {ai_report.get('remediation')}")

	# BƯỚC 8: REPORT OUTPUT
            report = generate_report(target_ip, port_info['port'], plugin, verify_result, validation, ai_report, rag_matches)
            all_reports.append(report)

            tier = report['finding']['classification']
            print(f"  │")
            print(f"  └─[BƯỚC 8] REPORT OUTPUT")
            print(f"     Classification : {tier}")
            print(f"     Severity       : {report['finding']['severity']}")
            print(f"     CVE/ID         : {meta['id']}")
            print(f"     CVSS Score     : {meta.get('cvss_score','N/A')}")
            print(f"     Rule Validated : {'✓' if validation['validated'] else '✗'}")
            print(f"     RAG References : {[r['cve'] for r in report['rag_references']]}")

    # Xuất báo cáo tổng hợp
    os.makedirs("report", exist_ok=True)
    report_file = f"report/vapt_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump({
            "summary": {
                "target": target_ip,
                "scan_time": datetime.datetime.now().isoformat(),
                "total_findings": len(all_reports),
                "confirmed": len([r for r in all_reports if r['finding']['status'] == 'CONFIRMED']),
                "potential": len([r for r in all_reports if r['finding']['status'] == 'PENDING']),
                "informational": len([r for r in all_reports if r['finding']['status'] == 'INFORMATIONAL']),
            },
            "findings": all_reports
        }, f, indent=2, ensure_ascii=False)

    print(f"\n{'='*60}")
    print(f"  PIPELINE HOÀN TẤT")
    print(f"  Report: {report_file}")
    confirmed = len([r for r in all_reports if r['finding']['status'] == 'CONFIRMED'])
    print(f"  Tổng  : {len(all_reports)} findings | {confirmed} Confirmed")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
