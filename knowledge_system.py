import sqlite3
import json
import time
from typing import Dict, Any, List, Optional

class KnowledgeSystem:
    def __init__(self, db_path: str = "knowledge_base.db"):
        self.db_path = db_path
        self._init_kb()

    def _init_kb(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # 1. PAYLOAD_KB: Lưu trữ các payload đột biến do AI sinh ra mang lại trạng thái HIT thành công
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS payload_kb (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    vuln_type TEXT,
                    technology_fingerprint TEXT,
                    successful_payload TEXT,
                    timestamp REAL,
                    use_count INTEGER DEFAULT 1
                )
            """)
            
            # 2. DECEPTION_KB: Lưu trữ dấu vết sinh học của các Honeypot đã bị bóc trần
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS deception_kb (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_host TEXT,
                    honeypot_signature_hash TEXT,
                    evidence_pattern TEXT,
                    timestamp REAL
                )
            """)
            
            # 3. EVIDENCE_KB: Lưu trữ các chuỗi Request/Response chứng minh lỗi tối giản phục vụ lập báo cáo
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS evidence_kb (
                    plugin_id TEXT PRIMARY KEY,
                    best_payload TEXT,
                    raw_proof_extracted TEXT,
                    confidence_score INTEGER,
                    timestamp REAL
                )
            """)
            conn.commit()

    # =========================================================================
    # NGHIỆP VỤ 1: QUẢN LÝ PAYLOAD TRI THỨC (PAYLOAD_KB)
    # =========================================================================
    def learn_successful_payload(self, vuln_type: str, fingerprint: str, payload: str):
        """Ghi nhận payload thành công vào kho tri thức để tái sử dụng"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, use_count FROM payload_kb 
                WHERE vuln_type = ? AND technology_fingerprint = ? AND successful_payload = ?
            """, (vuln_type, fingerprint, payload))
            row = cursor.fetchone()
            
            if row:
                cursor.execute("UPDATE payload_kb SET use_count = use_count + 1 WHERE id = ?", (row[0],))
            else:
                cursor.execute("""
                    INSERT INTO payload_kb (vuln_type, technology_fingerprint, successful_payload, timestamp)
                    VALUES (?, ?, ?, ?)
                """, (vuln_type, fingerprint, payload, time.time()))
            conn.commit()

    def query_optimized_payloads(self, vuln_type: str, fingerprint: str) -> List[str]:
        """Trích xuất các payload có tỷ lệ HIT cao nhất trong lịch sử cho một công nghệ"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT successful_payload FROM payload_kb 
                WHERE vuln_type = ? AND technology_fingerprint = ? 
                ORDER BY use_count DESC LIMIT 5
            """, (vuln_type, fingerprint))
            return [r[0] for r in cursor.fetchall()]

    # =========================================================================
    # NGHIỆP VỤ 2: QUẢN LÝ EVIDENCE BÁO CÁO (EVIDENCE_KB)
    # =========================================================================
    def save_golden_evidence(self, plugin_id: str, payload: str, proof: str, score: int):
        """Lưu biên lai bằng chứng vàng"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO evidence_kb (plugin_id, best_payload, raw_proof_extracted, confidence_score, timestamp)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(plugin_id) DO UPDATE SET
                    best_payload = excluded.best_payload,
                    raw_proof_extracted = excluded.raw_proof_extracted,
                    confidence_score = excluded.confidence_score,
                    timestamp = excluded.timestamp
            """, (plugin_id, payload, proof, score, time.time()))
            conn.commit()
