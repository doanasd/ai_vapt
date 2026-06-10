import urllib.request
import re
import time
from typing import Dict, Any
from plugins.base_plugin import BasePlugin
from interaction_logger import InteractionLogger

class DVWAWeakSessionPlugin(BasePlugin):
    def __init__(self):
        self.logger = InteractionLogger()

    @property
    def METADATA(self) -> Dict[str, Any]:
        return {
            "id": "DVWA-WEAK-SESSION",
            "name": "DVWA Weak Session ID",
            "cvss_score": 5.3,
            "service": "http",
            "vuln_type": "weak_session"
        }

    def match(self, service_info: Dict[str, Any]) -> bool:
        return service_info.get("service", "") in ["http", "https"]

    def verify(self, target_ip: str, target_port: int, context: Dict[str, Any]) -> Dict[str, Any]:
        cookie = context.get("session_cookie", "")
        if not cookie:
            return {"status": "PENDING", "evidence": "Chưa có session cookie"}

        url = f"http://{target_ip}:{target_port}/vulnerabilities/weak_id/"
        session_ids = []

        print(f"      [WeakSession] Thu thập 5 session ID liên tiếp...")
        for i in range(5):
            try:
                req = urllib.request.Request(url)
                req.add_header("Cookie", cookie)
                
                t0 = time.time()
                resp = urllib.request.urlopen(req, timeout=5)
                elapsed = round(time.time() - t0, 3)
                
                set_cookie = resp.getheader('Set-Cookie') or ""
                dvwa_session = re.search(r'dvwaSession=(\d+)', set_cookie)
                
                # Ghi nhận Telemetry thu thập ID liên tiếp
                self.logger.log_transaction(
                    plugin_id=self.METADATA["id"], target_ip=target_ip, target_port=target_port,
                    url=url, method="GET", payload=f"Iteration_{i}", req_headers={"Cookie": cookie},
                    res_status=resp.status, res_headers={}, res_body=set_cookie, latency=elapsed, marker_hit=bool(dvwa_session)
                )

                if dvwa_session:
                    sid = int(dvwa_session.group(1))
                    session_ids.append(sid)
                    print(f"      [WeakSession] Session #{i+1}: dvwaSession={sid}")
            except Exception:
                continue

        if len(session_ids) >= 3:
            diffs = [session_ids[i+1]-session_ids[i] for i in range(len(session_ids)-1)]
            is_sequential = all(d == 1 for d in diffs)
            if is_sequential:
                return {
                    "status": "CONFIRMED",
                    "confidence_metrics": {"final_score": 100, "rule_score": 100, "ai_score": 0, "deception_score": 0},
                    "evidence": f"Weak Session ID - ID tuần tự tăng đều +1: {session_ids}"
                }

        # Định dạng đầu ra an toàn khớp với cấu trúc mong đợi của main.py
        return {
            "status": "INFORMATIONAL",
            "confidence_metrics": {"final_score": 0, "rule_score": 0, "ai_score": 0, "deception_score": 0},
            "telemetry_summary": {"requests_analyzed": len(session_ids)},
            "evidence": f"Session IDs thu thập được: {session_ids}"
        }
