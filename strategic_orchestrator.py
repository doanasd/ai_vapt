import os
import json
from typing import Dict, Any

def ask_groq_brain(prompt: str) -> Dict[str, Any]:
    """
    Hàm gọi LLM chỉ huy - Phiên bản Expose Error phục vụ gỡ lỗi hệ thống
    """
    # 1. Kiểm tra sự tồn tại của API Key trước khi gọi mạng
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        print("[!] LỖI KỸ THUẬT: Biến môi trường 'GROQ_API_KEY' chưa được thiết lập!")
        return {
            "action": "TERMINATE", 
            "target_plugin": "", 
            "reason": "Thiếu biến môi trường GROQ_API_KEY trên máy chủ."
        }

    try:
        from groq import Groq
        client = Groq(api_key=api_key)
        
        # Sử dụng model tiêu chuẩn, có độ ổn định cao nhất của Groq
        # Bạn có thể đổi lại thành model cũ đang chạy được trong 'ai_self_validation.py' của bạn
        model_name = "llama3-70b-8192" 
        
        completion = client.chat.completions.create(
            model=model_name,
            messages=[
                {
                    "role": "system", 
                    "content": "You are a strategic offensive security director. You must always reply with a valid JSON object format."
                },
                {
                    "role": "user", 
                    "content": prompt
                }
            ],
            response_format={"type": "json_object"},
            temperature=0.1
        )
        
        raw_content = completion.choices[0].message.content
        return json.loads(raw_content)

    except Exception as e:
        # BẢN VÁ CHỮA LỖI: In trực tiếp Traceback lỗi thô của hệ thống ra màn hình terminal
        print(f"\n[!] LỖI KẾT NỐI API HOẶC HỆ THỐNG: {str(e)}")
        print(f"[!] Chi tiết kiểu ngoại lệ (Type): {type(e).__name__}")
        
        # Trả về fallback an toàn nhưng ghi nhận rõ thông tin lỗi hệ điều hành
        return {
            "action": "TERMINATE", 
            "target_plugin": "", 
            "reason": f"Hệ thống gặp ngoại lệ: {type(e).__name__} - {str(e)}"
        }
