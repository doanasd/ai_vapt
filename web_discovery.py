import urllib.request
import urllib.error
import subprocess
import json

DVWA_PATHS = [
    "vulnerabilities/sqli/",
    "vulnerabilities/sqli_blind/",
    "vulnerabilities/xss_r/",
    "vulnerabilities/xss_s/",
    "vulnerabilities/xss_d/",
    "vulnerabilities/exec/",
    "vulnerabilities/fi/",
    "vulnerabilities/upload/",
    "vulnerabilities/csrf/",
    "vulnerabilities/brute/",
    "vulnerabilities/weak_id/",
    "config/",
    "phpinfo.php",
    "setup.php",
]

# Map path → vulnerability type để plugin biết test gì
PATH_VULN_MAP = {
    "vulnerabilities/sqli/":       "sqli",
    "vulnerabilities/sqli_blind/": "sqli_blind",
    "vulnerabilities/xss_r/":      "xss_reflected",
    "vulnerabilities/xss_s/":      "xss_stored",
    "vulnerabilities/xss_d/":      "xss_dom",
    "vulnerabilities/exec/":       "command_injection",
    "vulnerabilities/fi/":         "lfi",
    "vulnerabilities/upload/":     "file_upload",
    "vulnerabilities/csrf/":       "csrf",
    "vulnerabilities/brute/":      "brute_force",
    "vulnerabilities/weak_id/":    "weak_session",
    "config/":                     "info_disclosure",
    "phpinfo.php":                  "info_disclosure",
    "setup.php":                    "info_disclosure",
}

def run_nikto(target_ip, port=80):
    print(f"  [Nikto] Scanning http://{target_ip}:{port}...")
    result = subprocess.run(
        ["nikto", "-h", f"http://{target_ip}:{port}", "-nossl", "-Format", "txt"],
        capture_output=True, text=True, timeout=60
    )
    findings = []
    for line in result.stdout.split('\n'):
        if line.startswith('+') and 'OSVDB' not in line and 'Start Time' not in line:
            findings.append(line.strip())
            print(f"  [Nikto] {line.strip()}")
    return findings

def discover_paths(target_ip, session_cookie, port=80):
    print(f"\n  [WebDiscover] Scanning {len(DVWA_PATHS)} paths trên {target_ip}:{port}")
    found = []
    for path in DVWA_PATHS:
        url = f"http://{target_ip}:{port}/{path}"
        try:
            req = urllib.request.Request(url)
            req.add_header("Cookie", session_cookie)
            resp = urllib.request.urlopen(req, timeout=5)
            vuln_type = PATH_VULN_MAP.get(path, "unknown")
            entry = {
                "path": f"/{path}",
                "url": url,
                "status": resp.getcode(),
                "vuln_type": vuln_type
            }
            found.append(entry)
            print(f"  [FOUND] {resp.getcode()}  /{path}  → vuln_type: {vuln_type}")
        except Exception as e:
            print(f"  [SKIP ]  /{path}  ({e})")
    
    print(f"\n  [WebDiscover] Tìm được {len(found)} endpoint active")
    return found
