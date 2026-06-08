import sys
import plugin_loader
import scanner
import ai_analyzer
import json

def main():
    if len(sys.argv) < 2:
        print("Cách dùng: python3 main.py <TARGET_IP>")
        sys.exit(1)
        
    target_ip = sys.argv[1]
    print(f"[*] Khởi động AI VAPT Orchestrator...")
    
    scan_results = scanner.run_scan(target_ip)
    plugins = plugin_loader.load_all_plugins()
    shared_memory_context = {}
    
    for port_info in scan_results:
        print(f"\n[*] Phân tích Port {port_info['port']} ({port_info['service']} {port_info['version']})...")
        for plugin in plugins:
            if plugin.match(port_info):
                print(f"[!] Kích hoạt chiến dịch: {plugin.METADATA['name']}")
                result = plugin.verify(target_ip, port_info["port"], context=shared_memory_context)
                print(f"   -> [STATUS]: {result['status']}")
                print(f"   -> [EVIDENCE]: {result['evidence']}")
                
                # BƯỚC 3 & 7: GỌI AI PHÂN TÍCH VÀ BÁO CÁO NẾU TÌM THẤY LỖ HỔNG
                if result['status'] == 'CONFIRMED':
                    ai_report = ai_analyzer.analyze_finding(plugin.METADATA, result)
                    print(f"   -> [AI REPORT]: {json.dumps(ai_report, indent=4, ensure_ascii=False)}")

if __name__ == "__main__":
    main()
