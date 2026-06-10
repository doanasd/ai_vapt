import json
from typing import Dict, Any, List
from deception_engine import DeceptionEngine

class ConfidenceEngine:
    def __init__(self):
        self.w_r = 0.5  # Trọng số Quy tắc cứng (Signature matching)
        self.w_a = 0.5  # Trọng số Trí tuệ nhân tạo (Semantic analysis)
        self.w_d = 1.0  # Trọng số Phát hiện đánh lừa (Deception penalty)
        self.deception_detector = DeceptionEngine()

    def calculate_score(
        self, 
        rule_passed: bool, 
        ai_verdict: str, 
        ai_confidence: int,
        telemetry_summary: Dict[str, Any]  # Nhận telemetry thô thay vì metrics tóm tắt
    ) -> Dict[str, Any]:
        
        # 1. Tính toán điểm Rule cứng
        rule_score = 100 if rule_passed else 0

        # 2. Tính toán điểm AI ngữ nghĩa
        ai_score = 0
        if ai_verdict.upper() in ["CONFIRMED", "VULNERABLE", "HIT"]:
            ai_score = max(0, min(100, ai_confidence))

        # 3. Kích hoạt Deception Engine phân tích động qua lịch sử Telemetry thô
        recent_history = telemetry_summary.get("recent_history", [])
        deception_score = self.deception_detector.analyze_deception(recent_history)

        # 4. Thuật toán tích hợp ma trận trọng số nâng cao
        final_score = (self.w_r * rule_score) + (self.w_a * ai_score) - (self.w_d * deception_score)
        final_score = max(0, min(100, round(final_score)))

        if final_score >= 75:  # Điều chỉnh ngưỡng phân hạng chuẩn Production
            verdict = "CONFIRMED"
        elif final_score >= 40:
            verdict = "SUSPECTED"
        else:
            verdict = "FALSE_POSITIVE"

        metrics = telemetry_summary.get("metrics", {})
        return {
            "verdict": verdict,
            "confidence_metrics": {
                "final_score": final_score,
                "rule_score": rule_score,
                "ai_score": ai_score,
                "deception_score": deception_score
            },
            "telemetry_summary": {
                "requests_analyzed": metrics.get("total_requests", len(recent_history)),
                "unique_content_hashes": metrics.get("unique_hashes_count", 1)
            }
        }
