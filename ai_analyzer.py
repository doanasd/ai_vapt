import os
import json
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

def analyze_finding(metadata, verify_result):
    print("      [AI Agent] Đang gửi Evidence cho Groq (llama-3.3-70b) phân tích...")
    client = Groq(api_key=os.getenv("GROQ_API_KEY"))
    
    prompt = f"""
    Bạn là chuyên gia AI VAPT. Hãy phân tích lỗ hổng sau và trả về JSON hợp lệ.
    - Tên lỗ hổng: {metadata['name']}
    - CVSS: {metadata.get('cvss_score', 'N/A')}
    - Bằng chứng trích xuất được: {verify_result['evidence']}
    
    Yêu cầu cấu trúc JSON duy nhất:
    {{
        "vulnerability": "Tên lỗ hổng",
        "impact": "Tác động ngắn gọn",
        "remediation": "Cách khắc phục ngắn gọn"
    }}
    """
    
    completion = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"}
    )
    
    # Đã sửa lỗi: Thêm  để lấy phần tử đầu tiên trong mảng choices
    return json.loads(completion.choices[0].message.content)
