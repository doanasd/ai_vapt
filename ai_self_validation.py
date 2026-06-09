import os
import json
from groq import Groq
from dotenv import load_dotenv

load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

def groq_generate_payloads(plugin_id, service, endpoint, initial_result):
    """
    AI Groq suy luận:
    1. Nếu đây là lỗ hổng thật, cần thêm bằng chứng gì?
    2. Sinh thêm payload để confirm
    3. Nghi ngờ honeypot — sinh payload phát hiện giả mạo
    """
    prompt = f"""Bạn là AI pentester đang tự kiểm chứng một finding.

CONTEXT:
- Plugin ID   : {plugin_id}
- Service     : {service}
- Endpoint    : {endpoint}
- Initial result: {json.dumps(initial_result, ensure_ascii=False)}

NHIỆM VỤ: Suy luận theo 3 bước:

BƯỚC A — Nếu đây là lỗ hổng THẬT, cần thêm bằng chứng gì?
Liệt kê 2-3 payload bổ sung để confirm thêm (không phải payload đã dùng).

BƯỚC B — Nghi ngờ HONEYPOT: output có thể bị dàn dựng không?
Honeypot thường trả về output "quá hoàn hảo", không có jitter, response time đều.
Sinh 1-2 payload để phát hiện honeypot (ví dụ: lệnh tạo file, đọc file không tồn tại, xem process thật).

BƯỚC C — Tổng kết: confidence level (0-100) và lý do nghi ngờ nếu có.

Trả về JSON hợp lệ:
{{
  "reasoning": "Suy luận ngắn gọn tại sao cần thêm verify",
  "confirm_payloads": [
    {{"payload": "...", "purpose": "...", "expect": "..."}},
    {{"payload": "...", "purpose": "...", "expect": "..."}}
  ],
  "honeypot_payloads": [
    {{"payload": "...", "purpose": "phát hiện honeypot", "expect": "..."}}
  ],
  "honeypot_suspicion": "low|medium|high",
  "honeypot_reason": "lý do nghi ngờ hoặc không nghi ngờ",
  "confidence_before_verify": 0-100
}}"""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"},
        temperature=0.3,
        max_tokens=1000
    )
    return json.loads(response.choices[0].message.content)


def groq_evaluate_results(plugin_id, all_results, honeypot_suspicion):
    """AI đánh giá toàn bộ kết quả và đưa ra verdict cuối"""
    prompt = f"""Bạn là AI security analyst đưa ra verdict cuối.

Plugin: {plugin_id}
Honeypot suspicion: {honeypot_suspicion}
Tất cả kết quả payload:
{json.dumps(all_results, ensure_ascii=False, indent=2)}

Đánh giá:
1. Các kết quả có nhất quán không? Hay có dấu hiệu bị dàn dựng?
2. Confidence level cuối cùng là bao nhiêu?
3. Verdict: CONFIRMED / FALSE_POSITIVE / PENDING / HONEYPOT_SUSPECTED

Trả về JSON:
{{
  "verdict": "CONFIRMED|FALSE_POSITIVE|PENDING|HONEYPOT_SUSPECTED",
  "confidence_final": 0-100,
  "consistency_check": "nhận xét về tính nhất quán của các kết quả",
  "honeypot_conclusion": "kết luận về khả năng honeypot",
  "final_reasoning": "lý do tổng hợp"
}}"""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"},
        temperature=0.1,
        max_tokens=500
    )
    return json.loads(response.choices[0].message.content)
