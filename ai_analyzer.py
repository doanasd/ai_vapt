import os
import json
from groq import Groq
from dotenv import load_dotenv

load_dotenv()
client_ai = Groq(api_key=os.getenv("GROQ_API_KEY"))

def ai_analyze(finding, cve_candidates):
    prompt = f"""Bạn là AI Security Analyst trong hệ thống AI VAPT.
Trả lời chỉ bằng JSON hợp lệ, không markdown, không giải thích.

SCAN FINDING:
  port: {finding['port']}
  service: {finding['service']}
  product: {finding['product']}
  version: {finding['version']}

CVE CANDIDATES:
{json.dumps(cve_candidates, indent=2)}

Trả về JSON:
{{
  "cve_match": "CVE-ID hoặc null",
  "confidence": 0-100,
  "is_false_positive_risk": true/false,
  "reason": "giải thích ngắn",
  "next_action": "verify hoặc skip",
  "severity": "Critical|High|Medium|Low|Informational"
}}"""

    response = client_ai.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
        max_tokens=500
    )
    text = response.choices[0].message.content.strip()
    text = text.replace("```json","").replace("```","").strip()
    return json.loads(text)

if __name__ == "__main__":
    test_finding = {"port":"21","service":"vsftpd","product":"vsftpd","version":"2.3.4"}
    test_cve = [{"id":"CVE-2011-2523","cvss":"10.0","description":"vsftpd backdoor"}]
    result = ai_analyze(test_finding, test_cve)
    print("[OK] Groq hoạt động:")
    print(json.dumps(result, indent=2, ensure_ascii=False))
