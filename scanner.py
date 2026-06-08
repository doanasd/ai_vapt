import subprocess
import xml.etree.ElementTree as ET
import json

def run_nmap(target_ip):
    print(f"[*] Đang scan {target_ip}...")
    subprocess.run([
        "nmap", "-sV", "-oX", "scan.xml", target_ip
    ], capture_output=True)
    return parse_nmap_xml("scan.xml")

def parse_nmap_xml(filepath):
    tree = ET.parse(filepath)
    root = tree.getroot()
    findings = []
    for port in root.iter('port'):
        state = port.find('state').get('state')
        if state == 'open':
            service = port.find('service')
            findings.append({
                "port": port.get('portid'),
                "protocol": port.get('protocol'),
                "service": service.get('name', ''),
                "product": service.get('product', ''),
                "version": service.get('version', '')
            })
    return findings

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    findings = run_nmap(target)
    print(f"[OK] Tìm được {len(findings)} port open:")
    for f in findings:
        print(f"  → port={f['port']} | {f['service']} | {f['product']} {f['version']}")
