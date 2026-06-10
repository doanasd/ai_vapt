import math
from typing import Dict, Any, List

class DeceptionEngine:
    def __init__(self):
        pass

    def analyze_deception(self, history: List[Dict[str, Any]]) -> int:
        """
        Deception Engine - Phiên bản tối ưu hóa diện miễn trừ toàn diện (CMDi, LFI, SQLi, UPLOAD, XSS)
        """
        if not history or len(history) < 2:
            return 0

        deception_score = 0
        hit_sessions = [log for log in history if log.get("marker_hit") == 1]
        total_hits = len(hit_sessions)

        # TẬP HỢP TẤT CẢ CHỮ KÝ CHỨNG MINH LỖ HỔNG THẬT ĐỂ TRÁNH PHẠT OAN LAN/LOCALHOST
        VULN_SIGNATURES = [
            "First name:", "Surname:",      # SQLi
            "[UNESCAPED_HIT]",              # XSS
            "uid=", "www-data",             # CMDi & File Upload RCE
            "root:x:", "daemon:x:"          # LFI
        ]

        if total_hits >= 2:
            hit_hashes = [s.get("response_hash") for s in hit_sessions if s.get("response_hash")]
            hit_lengths = [s.get("response_length", 0) for s in hit_sessions]
            hit_bodies = [s.get("response_body", "") for s in hit_sessions]
            
            unique_hit_hashes = len(set(hit_hashes))
            sample_body = hit_bodies[0] if hit_bodies else ""
            
            # Kiểm tra xem phản hồi thành công có chứa chữ ký của lỗ hổng thật hay không
            is_legit_vulnerability = any(sig in sample_body for sig in VULN_SIGNATURES)

            # Kỹ thuật 1: Kiểm tra tính vô cảm của chữ ký tĩnh (Static Response Hash)
            if unique_hit_hashes == 1:
                # Nếu mã băm trùng nhau nhưng nội dung chứa kết quả dump DB hoặc đọc file thật -> MIỄN TRỪ PHẠT
                if not is_legit_vulnerability:
                    deception_score += 60
                    print("      [Deception Warning] Phát hiện dấu hiệu bẫy phản hồi tĩnh giả lập!")

            # Kỹ thuật 2: Phân tích biến động độ dài phản hồi thành công (Zero Length Variance)
            avg_hit_len = sum(hit_lengths) / total_hits
            hit_len_variance = sum((x - avg_hit_len) ** 2 for x in hit_lengths) / total_hits
            
            if hit_len_variance == 0:
                # Nếu kích thước không đổi nhưng là do kết quả lệnh/file trả về cố định -> MIỄN TRỪ PHẠT
                if not is_legit_vulnerability:
                    deception_score += 30  
                    print("      [Deception Warning] Biến động kích thước dữ liệu HIT bằng 0 phi lý!")

        # Kỹ thuật 3: Bẫy kiểm tra payload giả định lỗi (Honeypot/Non-existent triggers)
        for log in history:
            purpose = log.get("purpose", "").lower()
            if ("honeypot" in purpose or "non-existent" in purpose) and log.get("marker_hit") == 1:
                deception_score += 90

        return min(100, deception_score)
