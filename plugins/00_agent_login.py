import urllib.request
import urllib.parse
import re
import time
from typing import Dict, Any
from plugins.base_plugin import BasePlugin
from interaction_logger import InteractionLogger

CREDENTIAL_LIST = [
    ("admin", "password"),
    ("admin", "admin"),
    ("admin", "123456"),
    ("user", "user"),
]

class DVWALoginAgent(BasePlugin):
    def __init__(self):
        self.logger = InteractionLogger()

    @property
    def METADATA(self) -> Dict[str, Any]:
        return {
            "id": "AGENT-001",
            "name": "Tự động đăng nhập & Trích xuất Session",
            "cvss_score": 0.0,
            "service": "http",
            "version": "dvwa",
            "vuln_type": "authentication",  # Thêm trường này để xử lý lỗi KeyError trong main.py
            "note": "Agent nội bộ - không phải CVE, CVSS=0"
        }

    def match(self, service_info: Dict[str, Any]) -> bool:
        return service_info.get("service", "").lower() in ["http", "https"]

    def verify(self, target_ip: str, target_port: int, context: Dict[str, Any]) -> Dict[str, Any]:
        try:
            login_url = f"http://{target_ip}:{target_port}/login.php"
            print(f"      [Agent] Trinh sát form đăng nhập: {login_url}")

            req1 = urllib.request.Request(login_url)
            t0 = time.time()
            resp1 = urllib.request.urlopen(req1, timeout=5)
            elapsed1 = round(time.time() - t0, 3)
            html = resp1.read().decode('utf-8')
            cookie_header = resp1.getheader('Set-Cookie')

            phpsessid = re.search(r'(PHPSESSID=[a-zA-Z0-9]+)', str(cookie_header)).group(1)
            user_token = re.search(r"name='user_token' value='([a-f0-9]+)'", html).group(1)

            print(f"      [Agent] PHPSESSID    : {phpsessid}")
            print(f"      [Agent] CSRF Token   : {user_token}")

            for username, password in CREDENTIAL_LIST:
                print(f"      [Agent] Thử: {username}:{password} ...")
                data = urllib.parse.urlencode({
                    'username': username,
                    'password': password,
                    'Login': 'Login',
                    'user_token': user_token
                }).encode('utf-8')

                req2 = urllib.request.Request(login_url, data=data)
                req2.add_header("Cookie", phpsessid)
                
                t1 = time.time()
                resp2 = urllib.request.urlopen(req2, timeout=5)
                elapsed2 = round(time.time() - t1, 3)
                final_url = resp2.geturl()

                # Ghi nhận Telemetry cho mỗi lượt Brute-force
                success = "login.php" not in final_url
                self.logger.log_transaction(
                    plugin_id=self.METADATA["id"], target_ip=target_ip, target_port=target_port,
                    url=login_url, method="POST", payload=f"{username}:{password}",
                    req_headers={"Cookie": phpsessid}, res_status=resp2.status, res_headers={},
                    res_body=final_url, latency=elapsed2, marker_hit=success
                )

                if success:
                    session_cookie = f"security=low; {phpsessid}"
                    context["session_cookie"] = session_cookie
                    context["credential"] = f"{username}:{password}"

                    print(f"      [Agent] ✓ Login thành công: {username}:{password}")
                    return {
                        "status": "INFORMATIONAL",
                        "evidence": f"Default credential thành công: {username}:{password}"
                    }

            return {"status": "FALSE_POSITIVE", "evidence": "Không brute-force được với credential list hiện tại"}

        except Exception as e:
            return {"status": "PENDING", "evidence": f"Lỗi Agent Login: {str(e)}"}
