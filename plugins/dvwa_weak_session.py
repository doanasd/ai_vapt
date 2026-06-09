import urllib.request
import re
from typing import Dict, Any
from plugins.base_plugin import BasePlugin

class DVWAWeakSessionPlugin(BasePlugin):
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
        return service_info.get("service","") in ["http","https"]

    def verify(self, target_ip: str, target_port: int, context: Dict[str, Any]) -> Dict[str, Any]:
        cookie = context.get("session_cookie","")
        if not cookie:
            return {"status": "PENDING", "evidence": "Chưa có session cookie"}

        url = f"http://{target_ip}:{target_port}/vulnerabilities/weak_id/"
        session_ids = []

        print(f"      [WeakSession] Thu thập 5 session ID liên tiếp...")
        for i in range(5):
            try:
                req = urllib.request.Request(url)
                req.add_header("Cookie", cookie)
                resp = urllib.request.urlopen(req, timeout=5)
                set_cookie = resp.getheader('Set-Cookie') or ""
                dvwa_session = re.search(r'dvwaSession=(\d+)', set_cookie)
                if dvwa_session:
                    sid = int(dvwa_session.group(1))
                    session_ids.append(sid)
                    print(f"      [WeakSession] Session #{i+1}: dvwaSession={sid}")
            except Exception as e:
                continue

        if len(session_ids) >= 3:
            diffs = [session_ids[i+1]-session_ids[i] for i in range(len(session_ids)-1)]
            is_sequential = all(d == 1 for d in diffs)
            if is_sequential:
                return {
                    "status": "CONFIRMED",
                    "evidence": (
                        f"Weak Session ID - ID tuần tự, dễ đoán.\n"
                        f"      - URL          : {url}\n"
                        f"      - Session IDs  : {session_ids}\n"
                        f"      - Pattern      : tăng dần đều +1\n"
                        f"      - Risk         : attacker có thể brute force session ID"
                    )
                }

        return {"status": "INFORMATIONAL", "evidence": f"Session IDs thu thập được: {session_ids}"}
