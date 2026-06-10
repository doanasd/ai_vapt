import urllib.request
import urllib.parse
import time
import json
from typing import Dict, Any
from plugins.base_plugin import BasePlugin
from interaction_logger import InteractionLogger
from confidence_engine import ConfidenceEngine

class DVWAXSSPlugin(BasePlugin):
    def __init__(self):
        self.logger = InteractionLogger()
        self.engine = ConfidenceEngine()

    @property
    def METADATA(self) -> Dict[str, Any]:
        return {
            "id": "DVWA-XSS",
            "name": "DVWA XSS Reflected (Autonomous Stage)",
            "cvss_score": 6.1,
            "service": "http",
            "vuln_type": "xss_reflected"
        }

    def match(self, service_info: Dict[str, Any]) -> bool:
        return service_info.get("service", "") in ["http", "https"]

    def _send_payload(self, base_url, target_ip, target_port, payload, cookie):
        """Gửi XSS Payload và phân tích vi sai sự xuất hiện của cấu trúc unescaped"""
        try:
            encoded_payload = urllib.parse.quote(payload)
            full_url = f"{base_url}?name={encoded_payload}"
            req = urllib.request.Request(full_url)
            req.add_header("Cookie", cookie)
            
            t0 = time.time()
            resp = urllib.request.urlopen(req, timeout=5)
            elapsed = round(time.time() - t0, 3)
            body = resp.read().decode('utf-8', errors='ignore')
            
            output = ""
            if payload in body:
                idx = body.find(payload)
                start = max(0, idx - 30)
                end = min(len(body), idx + len(payload) + 30)
                output = f"[UNESCAPED_HIT] Context: ...{body[start:end].strip()}..."
            else:
                output = "[ESCAPED_OR_MISS] Payload bị lọc mã hóa hoặc biến mất."

            marker_hit = "[UNESCAPED_HIT]" in output

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
            return {"status": "PENDING", "evidence": "Shared_context thiếu session_cookie."}

        url = f"http://{target_ip}:{target_port}/vulnerabilities/xss_r/"
        kb_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"]
        initial_confirmed = None

        print(f"      [XSS-Autonomous] Vòng 1: Kiểm thử XSS Reflected...")
        for payload in kb_payloads:
            res = self._send_payload(url, target_ip, target_port, payload, cookie)
            if res["hit"]:
                initial_confirmed = {"payload": payload, "output": res["output"]}
                break

        if not initial_confirmed:
            return {"status": "FALSE_POSITIVE", "evidence": "Mục tiêu lọc thực thể XSS an toàn hoặc áp dụng mã hóa đầu ra."}

        telemetry_summary = self.logger.get_plugin_telemetry(self.METADATA["id"])
        decision = self.engine.calculate_score(
            rule_passed=True, ai_verdict="CONFIRMED", ai_confidence=88, telemetry_summary=telemetry_summary
        )

        return {
            "status": decision["verdict"],
            "confidence_metrics": decision["confidence_metrics"],
            "telemetry_summary": decision["telemetry_summary"],
            "evidence": (
                f"XSS Reflected — Xác thực thành công.\n"
                f"      - Payload tốt nhất  : {initial_confirmed['payload']}\n"
                f"      - Điểm toán học     : {json.dumps(decision['confidence_metrics'])}\n"
                f"      - Ngữ cảnh HTML khớp: {initial_confirmed['output']}"
            )
        }
