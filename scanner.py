import subprocess

def run_scan(target_ip):
    print(f"[*] Đang chạy Nmap scan trên {target_ip}...")
    result = subprocess.run(['nmap', '-p', '21,80,8080', '-sV', target_ip], capture_output=True, text=True)

    parsed_results = []
    for line in result.stdout.split('\n'):
        if ' open ' in line:
            parts = line.split()
            port = int(parts[0].split('/')[0])
            service = parts[2] if len(parts) > 2 else ""
            version = " ".join(parts[3:]) if len(parts) > 3 else ""
            parsed_results.append({"port": port, "service": service, "version": version})

    print(f"[*] Context Optimization: giữ lại {len(parsed_results)} port OPEN.")
    return parsed_results
