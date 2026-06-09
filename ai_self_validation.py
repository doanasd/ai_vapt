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
    prompt = f"""Bạn là một chuyên gia Security Analyst (Pentester) thực tế và cực kỳ khắt khe.

Plugin đang kiểm tra: {plugin_id}
Honeypot suspicion từ phase trước: {honeypot_suspicion}
Tất cả kết quả payload thực thi:
{json.dumps(all_results, ensure_ascii=False, indent=2)}

QUY TẮC ĐÁNH GIÁ (TUYỆT ĐỐI TUÂN THỦ):
1. KHÔNG ĐƯỢC ẢO GIÁC (NO HALLUCINATION). Bạn chỉ được phép kết luận là thành công nếu output THỰC SỰ chứa dữ liệu của hệ thống (ví dụ: uid, www-data, nội dung /etc/passwd, v.v.).
2. Cảnh báo ping: Nếu output CHỈ hiển thị kết quả của lệnh ping (ví dụ: 'PING 127.0.0.1... 64 bytes from...') mà không có thông tin hệ thống nào khác, bạn PHẢI đánh giá payload đó là THẤT BẠI.
3. Cảnh báo Blind/Timeout: Nếu output chứa dòng chữ '[SYSTEM_TIMEOUT]', và payload tương ứng có chứa các lệnh gây delay (như 'sleep 5'), đó là BẰNG CHỨNG MẠNH MẼ cho thấy lỗ hổng thực sự tồn tại (Blind Injection).
4. Phân tích Honeypot: Nếu các lỗi cấu hình ngớ ngẩn (cat /etc/nonexist) mà vẫn trả về 200 OK hoặc ra output giả mạo, hãy đánh giá HONEYPOT_SUSPECTED.

Nhiệm vụ:
1. Đánh giá tính nhất quán của các kết quả.
2. Đưa ra Verdict cuối cùng: CONFIRMED / FALSE_POSITIVE / PENDING / HONEYPOT_SUSPECTED

Trả về JSON:
{{
  "verdict": "CONFIRMED|FALSE_POSITIVE|PENDING|HONEYPOT_SUSPECTED",
  "confidence_final": 0-100,
  "consistency_check": "Phân tích output có thực sự chứa bằng chứng nhạy cảm hay chỉ là mồi nhử (ping)?",
  "honeypot_conclusion": "Kết luận về honeypot",
  "final_reasoning": "Lý do chi tiết dựa trên bằng chứng (trích dẫn text cụ thể từ output)"
}}"""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"},
        temperature=0.1,
        max_tokens=500
    )
    return json.loads(response.choices[0].message.content)
