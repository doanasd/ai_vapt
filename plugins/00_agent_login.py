import urllib.request
import urllib.parse
import re
from typing import Dict, Any
from plugins.base_plugin import BasePlugin

class DVWALoginAgent(BasePlugin):
    @property
    def METADATA(self) -> Dict[str, Any]:
        return {
            "id": "AGENT-001",
            "name": "Tự động đăng nhập & Trích xuất Session",
            "cvss_score": 0.0,
            "service": "http",
            "version": "dvwa"
        }

    def match(self, service_info: Dict[str, Any]) -> bool:
        return service_info.get("service", "").lower() in ["http", "https"]

    def verify(self, target_ip: str, target_port: int, context: Dict[str, Any]) -> Dict[str, Any]:
        try:
            print(f"      [Agent] Đang trinh sát form đăng nhập tại {target_ip}...")
            # 1. Gọi request đầu tiên để lấy PHPSESSID và CSRF Token (Mô phỏng Parser Agent)
            login_url = f"http://{target_ip}:{target_port}/login.php"
            req1 = urllib.request.Request(login_url)
            resp1 = urllib.request.urlopen(req1, timeout=5)
            html = resp1.read().decode('utf-8')
            
            cookie_header = resp1.getheader('Set-Cookie')
            phpsessid = re.search(r'(PHPSESSID=[a-zA-Z0-9]+)', str(cookie_header)).group(1)
            user_token = re.search(r"name='user_token' value='([a-f0-9]+)'", html).group(1)
            
            print(f"      [Agent] Đã bóc tách CSRF Token: {user_token[:6]}... Đang Brute-force...")
            
            # 2. Gửi payload đăng nhập mặc định (admin:password)
            data = urllib.parse.urlencode({
                'username': 'admin', 'password': 'password', 'Login': 'Login', 'user_token': user_token
            }).encode('utf-8')
            
            req2 = urllib.request.Request(login_url, data=data)
            req2.add_header("Cookie", phpsessid)
            resp2 = urllib.request.urlopen(req2, timeout=5)
            
            # 3. Nạp Session Cookie thật vào Bộ nhớ Context để truyền cho các module phía sau
            context["session_cookie"] = f"security=low; {phpsessid}"
            
            return {"status": "INFORMATIONAL", "evidence": f"Đăng nhập thành công! Đã nạp Cookie vào Context."}
            
        except Exception as e:
            return {"status": "PENDING", "evidence": f"Lỗi Agent Login: {str(e)}"}
