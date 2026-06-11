import os
import sys
import json
import time
import argparse

# Import bộ điều phối chiến lược và trình tải module của bạn
from plugin_loader import load_all_plugins
from strategic_orchestrator import ask_groq_brain

# Import các hàm chạy trinh sát bề mặt sẵn có từ hệ thống của bạn
# (Tùy biến tên hàm chính xác theo cấu trúc xuất bản bên trong các file của bạn)
try:
    from scanner import run_nmap_scan
    from web_discovery import discover_web_endpoints
except ImportError:
    # Cơ chế fallback hiển thị cảnh báo nếu cấu trúc file thành phần bị di dời
    run_nmap_scan = None
    discover_web_endpoints = None

def end_to_end_pipeline():
    # Thiết lập trình phân tích tham số dòng lệnh đầu vào
    parser = argparse.ArgumentParser(description="Autonomous AI-Driven VAPT Platform - Level 5")
    parser.add_argument("target", help="Địa chỉ mục tiêu kiểm thử (Ví dụ: 13.229.112.6 hoặc http://target.com)")
    args = parser.parse_args()

    target = args.target
    print(f"============================================================")
    print(f"AI VAPT PIPELINE ĐỘNG THỜI GIAN THỰC — MỤC TIÊU: {target}")
    print(f"Thời gian khởi chạy: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"============================================================")

    # Khởi tạo khung ngữ cảnh trống để nạp dữ liệu động trong suốt quá trình chạy
    shared_context = {
        "service": "unknown",
        "version": "unknown",
        "vulnerable_paths": [],
        "session_cookie": None
    }

    # ────────────────────────────────────────────────────────────
    # TẦNG 1 & 2: NETWORK RECON & CONTEXT OPTIMIZATION
    # ────────────────────────────────────────────────────────────
    target_ip = target.replace("http://", "").replace("https://", "").split(":")[0].split("/")[0]
    target_port = 80 # Mặc định cho HTTP dịch vụ Web

    if run_nmap_scan:
        print("\n[+] KHỞI CHẠY TẦNG 1: TRINH SÁT HẠ TẦNG MẠNG (NMAP/NIKTO)...")
        # Gọi module quét thô để lấy thông tin cổng và dịch vụ thực tế
        recon_result = run_nmap_scan(target_ip)
        
        print("\n[+] KHỞI CHẠY TẦNG 2: TỐI ƯU HÓA NGỮ CẢNH (PARSER AGENT)...")
        # Trích xuất dữ liệu phi cấu trúc từ log quét thành dữ liệu sạch
        shared_context["service"] = recon_result.get("detected_service", "http")
        shared_context["version"] = recon_result.get("service_version", "Apache httpd 2.4.25")
        target_port = recon_result.get("detected_port", 80)
    else:
        print("\n[-] Cảnh báo: Không tìm thấy module 'scanner.py'. Sử dụng cấu hình trinh sát mặc định.")
        shared_context["service"] = "http"
        shared_context["version"] = "Apache httpd 2.4.25"

    # ────────────────────────────────────────────────────────────
    # ĐOÀN THÁM HIỂM ENDPOINT VÀ ĐĂNG NHẬP TỰ ĐỘNG
    # ────────────────────────────────────────────────────────────
    if discover_web_endpoints and shared_context["service"] in ["http", "https"]:
        print("\n[+] KHỞI CHẠY ĐỒ CHƠI TRINH SÁT WEB & ĐĂNG NHẬP FORM TỰ ĐỘNG...")
        discovery_data = discover_web_endpoints(target_ip, target_port)
        shared_context["vulnerable_paths"] = discovery_data.get("paths", [])

    # Nạp kho vũ khí plugin có sẵn
    plugins = load_all_plugins()

    # Kiểm tra điều kiện sinh tồn tối thiểu trước khi chuyển giao quyền lực cho AI
    if not plugins:
        print("[!] Lỗi nghiêm trọng: Kho chứa không có Plugin nào được nạp thành công. Hủy phiên quét.")
        sys.exit(1)

    # ────────────────────────────────────────────────────────────
    # TẦNG 3 ĐẾN 7: KHỞI CHẠY BỘ NÃO CHIẾN LƯỢC TỰ CHỦ
    # ────────────────────────────────────────────────────────────
    # Tại điểm này, các plugin như AGENT-001 sẽ tự động lấy thông tin từ shared_context,
    # thực hiện brute force form thu được động để lấy session_cookie và cập nhật ngược lại luồng chạy.
    orchestrator = ask_groq_brain(plugins)
    final_report = orchestrator.coordinate_attack(target_ip, target_port, shared_context)

    # Đóng gói và lưu trữ báo cáo Production sạch
    os.makedirs("report", exist_ok=True)
    report_filename = f"report/vapt_strategic_report_{time.strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_filename, "w", encoding="utf-8") as f:
        json.dump(final_report, f, indent=4, ensure_ascii=False)
        
    print(f"\n[✓] PIPELINE HOÀN TẤT — Báo cáo chiến lược động đã xuất bản: {report_filename}")

if __name__ == "__main__":
    # Bảo vệ an toàn luồng tránh các ngoại lệ hệ thống ngoài danh mục
    try:
        end_to_end_pipeline()
    except KeyboardInterrupt:
        print("\n[!] Người vận hành phát lệnh ngắt phiên quét khẩn cấp (Ctrl+C).")
        sys.exit(0)
