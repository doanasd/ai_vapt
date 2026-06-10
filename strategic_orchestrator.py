import json
import time
from typing import Dict, Any, List
from confidence_engine import ConfidenceEngine
from knowledge_system import KnowledgeSystem  # Kế thừa Phase 6

# Giả lập hàm gọi API Groq từ module có sẵn của bạn
# Trong thực tế, hàm này sẽ gửi prompt sang cho Llama-3.3-70b qua Groq
def ask_groq_brain(prompt: str) -> Dict[str, Any]:
    from groq import Groq  # Giả định bạn cài đặt groq client
    try:
        client = Groq()
        completion = client.chat.completions.create(
            model="llama-3.3-70b-specdec",
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            temperature=0.1
        )
        return json.loads(completion.choices[0].message.content)
    except Exception:
        # Fallback logic nếu nghẽn API
        return {"action": "TERMINATE", "target_plugin": "", "reason": "Groq API Limit / Connection Reset"}

class StrategicOrchestrator:
    def __init__(self, plugins: List[Any]):
        self.plugins = {p.METADATA["id"]: p for p in plugins}
        self.engine = ConfidenceEngine()
        self.history_log = []
        self.scan_summary = {}

    def _build_strategic_prompt(self, target: str, available_plugins: List[Dict[str, Any]]) -> str:
        return f"""
        Bạn là Autonomous Strategic Decision Engine - Bộ não chỉ huy tối cao của hệ thống AI VAPT.
        Nhiệm vụ của bạn là phân tích trạng thái hiện tại và đưa ra hành động tiếp theo.

        [MỤC TIÊU]
        Target: {target}

        [CÁC PLUGIN SẴN CÓ TRONG HỆ THỐNG]
        {json.dumps(available_plugins, indent=2, ensure_ascii=False)}

        [LỊCH SỬ TẤN CÔNG VÀ KẾT QUẢ ĐÃ THU THẬP THỜI GIAN THỰC]
        {json.dumps(self.history_log, indent=2, ensure_ascii=False)}

        [YÊU CẦU ĐẦU RA]
        Bạn phải trả về một đối tượng JSON chứa quyết định chiến lược tiếp theo, không được trả về text giải thích.
        Định dạng JSON bắt buộc:
        {{
            "action": "PLAN" hoặc "RETRY" hoặc "PIVOT" hoặc "TERMINATE",
            "target_plugin": "Mã ID của plugin bạn muốn chạy tiếp theo (Ví dụ: DVWA-SQLI)",
            "reason": "Giải thích logic tại sao bạn chọn hành động này dựa trên bằng chứng thu được"
        }}
        """

    def coordinate_attack(self, target_ip: str, target_port: int, shared_context: Dict[str, Any]) -> Dict[str, Any]:
        print("\n[+] KÍCH HOẠT BỘ ĐIỀU PHỐI CHIẾN LƯỢC TỰ CHỦ (PHASE 7 - NO HARDCODED)")
        
        target_str = f"{target_ip}:{target_port}"
        available_meta = [p.METADATA for p in self.plugins.values()]
        
        is_running = True
        loop_counter = 0
        max_loops = 12  # Ngăn chặn vòng lặp vô hạn (Infinite Loop Boundary)

        while is_running and loop_counter < max_loops:
            loop_counter += 1
            print(f"\n[Vòng Quyết Định #{loop_counter}] AI đang lập luận chiến thuật tấn công...")

            # 1. Gọi Llama 3.3 70B đóng vai trò chỉ huy quân sự đưa ra quyết định
            prompt = self._build_strategic_prompt(target_str, available_meta)
            decision = ask_groq_brain(prompt)
            
            action = decision.get("action", "TERMINATE")
            target_plugin_id = decision.get("target_plugin", "")
            reason = decision.get("reason", "No reason provided by AI.")

            print(f"      [AI Decision] Quyết định hành động: {action}")
            print(f"      [AI Target  ] Mục tiêu tiếp theo : {target_plugin_id}")
            print(f"      [AI Reason  ] Lập luận chiến lược: {reason}")

            if action == "TERMINATE" or not target_plugin_id:
                print("[!] AI quyết định đóng phiên quét bảo mật (Strategic Termination).")
                is_running = False
                break

            if target_plugin_id not in self.plugins:
                print(f"[-] AI chọn sai ID Plugin '{target_plugin_id}' không tồn tại. Tự động chuyển hướng...")
                continue

            # 2. Thực thi Plugin dựa trên quyết định động của AI
            plugin = self.plugins[target_plugin_id]
            meta = plugin.METADATA

            # Kiểm tra nhanh trùng lặp để tránh AI bị kẹt vòng lặp vô hạn vào một plugin lỗi
            already_run = any(h["plugin_id"] == target_plugin_id and h["status"] in ["CONFIRMED", "FALSE_POSITIVE"] for h in self.history_log)
            if already_run and action != "RETRY":
                print(f"[-] Plugin {target_plugin_id} đã chạy xong trước đó. Ép AI đổi hướng chiến thuật.")
                continue

            print(f"      [Executing] Khởi hỏa hệ thống: {meta['name']}...")
            try:
                # Thực thi tầng quét tự chủ của Plugin
                result = plugin.verify(target_ip, target_port, shared_context)
                
                # Lưu lịch sử chạy vào bộ nhớ ngắn hạn để lượt lập luận tiếp theo AI có thể đọc được
                history_entry = {
                    "plugin_id": target_plugin_id,
                    "status": result.get("status", "FALSE_POSITIVE"),
                    "confidence_score": result.get("confidence_metrics", {}).get("final_score", 0),
                    "evidence_summary": result.get("evidence", "")[:150]
                }
                self.history_log.append(history_entry)

                # CẬP NHẬT CHUỖI TRI THỨC ĐỘT BIẾN ĐỂ PIVOT (Nếu thu thập được session cookie mới hoặc dữ liệu nhạy cảm)
                if "session_cookie" in shared_context:
                    pass  # Đã có mã định danh phiên

            except Exception as e:
                print(f"      [!] Lỗi thực thi Plugin {target_plugin_id}: {str(e)}")
                self.history_log.append({"plugin_id": target_plugin_id, "status": "ERROR", "error": str(e)})
                continue

        # Đóng gói xuất báo cáo cuối cùng
        report = {
            "target": target_str,
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "strategic_path_length": len(self.history_log),
            "findings_summary": self.history_log
        }
        return report
