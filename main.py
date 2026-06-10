import os
import json
import time
from plugin_loader import load_all_plugins
from interaction_logger import InteractionLogger
from confidence_engine import ConfidenceEngine

def autonomous_orchestrator(target_ip: str, target_port: int, shared_context: dict):
    print("\n[+] KHỞI CHẠY BỘ ĐIỀU PHỐI TRUNG TÂM — AUTONOMOUS CORE")
    
    # Khởi tạo nền tảng dùng chung cho toàn bộ Pipeline
    logger = InteractionLogger()
    engine = ConfidenceEngine()
    
    # Giả lập danh sách plugin được nạp từ hệ thống cũ
    # Trong thực tế, phần này sẽ gọi plugin_loader của bạn
    plugins = load_all_plugins()
    
    final_report = {
        "target": f"{target_ip}:{target_port}",
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "findings": []
    }

    for plugin in plugins:
        meta = plugin.METADATA
        print(f"\n────────────────────────────────────────────────────────────")
        print(f"[+] Kích hoạt Plugin: {meta['name']} [{meta['id']}]")
        
        # Kiểm tra điều kiện khớp dịch vụ từ Layer 2
        if not plugin.match({"service": shared_context.get("service", "http")}):
            print(f"[-] Plugin {meta['id']} không phù hợp với dịch vụ mục tiêu. Bỏ qua.")
            continue

        try:
            # Thực thi tầng xác thực tự chủ của Plugin
            # Kết quả trả về bây giờ bao gồm cấu trúc Scoring toán học
            result = plugin.verify(target_ip, target_port, shared_context)
            
            # Chuẩn hóa và đóng gói cấu trúc dữ liệu xuất xưởng
            finding_entry = {
                "plugin_id": meta["id"],
                "vulnerability": meta["name"],
                "cvss_score": meta["cvss_score"],
                "vuln_type": meta["vuln_type"],
                "status": result.get("status", "FALSE_POSITIVE"),
                "evidence_text": result.get("evidence", ""),
                "confidence_metrics": result.get("confidence_metrics", {
                    "final_score": 0, "rule_score": 0, "ai_score": 0, "deception_score": 0
                }),
                "telemetry_summary": result.get("telemetry_summary", {})
            }
            
            final_report["findings"].append(finding_entry)
            print(f"[✓] Hoàn tất xử lý định lượng cho {meta['id']}. Trạng thái: {result.get('status')}")
            
        except Exception as e:
            print(f"[!] Lỗi nghiêm trọng khi thực thi Plugin {meta['id']}: {str(e)}")
            # Quy tắc sống còn: Không ngắt luồng (No Pipeline Short-circuit), tiếp tục duyệt plugin khác
            continue

    # Xuất báo cáo cấu trúc JSON nâng cao
    os.makedirs("report", exist_ok=True)
    report_filename = f"report/vapt_autonomous_report_{time.strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_filename, "w", encoding="utf-8") as f:
        json.dump(final_report, f, indent=4, ensure_ascii=False)
        
    print(f"\n[+] PIPELINE HOÀN TẤT — Báo cáo định lượng đã ghi ra: {report_filename}")
    return final_report

if __name__ == "__main__":
    # 1. Cấu hình thông tin mục tiêu (Target) thu được từ Layer 1 & 2
    target_ip = "13.229.112.6"
    target_port = 80
    
    # 2. Đồng bộ shared_context chứa session cookie đã brute-force thành công từ tầng trinh sát
    shared_context = {
        "service": "http",
        "version": "Apache httpd 2.4.25",
        "session_cookie": "security=low; PHPSESSID=570ea3c1sllgm9fcdlo5c9n1u7"
    }
    
    # 3. Kích hoạt toàn bộ Pipeline tự chủ vận hành
    autonomous_orchestrator(target_ip, target_port, shared_context)
