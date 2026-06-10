import sqlite3
import json
import time
import hashlib
from typing import Dict, Any, Optional

class InteractionLogger:
    def __init__(self, db_path: str = "telemetry.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS interaction_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    plugin_id TEXT,
                    target_ip TEXT,
                    target_port INTEGER,
                    request_url TEXT,
                    request_method TEXT,
                    payload TEXT,
                    request_headers TEXT,
                    response_status INTEGER,
                    response_headers TEXT,
                    response_body TEXT,
                    response_hash TEXT,
                    response_length INTEGER,
                    latency REAL,
                    marker_hit INTEGER
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metrics_summary (
                    plugin_id TEXT PRIMARY KEY,
                    total_requests INTEGER,
                    avg_latency REAL,
                    latency_variance REAL,
                    unique_hashes_count INTEGER,
                    entropy_score REAL
                )
            """)
            conn.commit()

    def log_transaction(
        self, 
        plugin_id: str, 
        target_ip: str, 
        target_port: int, 
        url: str, 
        method: str, 
        payload: str, 
        req_headers: Dict[str, str], 
        res_status: Optional[int], 
        res_headers: Dict[str, str], 
        res_body: str, 
        latency: float, 
        marker_hit: bool
    ) -> int:
        response_bytes = res_body.encode('utf-8', errors='ignore')
        res_hash = hashlib.sha256(response_bytes).hexdigest()
        res_length = len(response_bytes)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO interaction_logs (
                    timestamp, plugin_id, target_ip, target_port, request_url, 
                    request_method, payload, request_headers, response_status, 
                    response_headers, response_body, response_hash, response_length, 
                    latency, marker_hit
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                time.time(), plugin_id, target_ip, target_port, url,
                method, payload, json.dumps(req_headers), res_status,
                json.dumps(res_headers), res_body, res_hash, res_length,
                latency, 1 if marker_hit else 0
            ))
            conn.commit()
            last_id = cursor.lastrowid
            
        self._update_metrics_summary(plugin_id)
        return last_id

    def _update_metrics_summary(self, plugin_id: str):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT latency, response_hash FROM interaction_logs WHERE plugin_id = ?
            """, (plugin_id,))
            rows = cursor.fetchall()
            
            if not rows:
                return
                
            total = len(rows)
            latencies = [r[0] for r in rows]
            hashes = set([r[1] for r in rows])
            
            avg_latency = sum(latencies) / total
            variance = sum((x - avg_latency) ** 2 for x in latencies) / total if total > 1 else 0.0
            
            cursor.execute("""
                INSERT INTO metrics_summary (plugin_id, total_requests, avg_latency, latency_variance, unique_hashes_count, entropy_score)
                VALUES (?, ?, ?, ?, ?, 0.0)
                ON CONFLICT(plugin_id) DO UPDATE SET
                    total_requests = excluded.total_requests,
                    avg_latency = excluded.avg_latency,
                    latency_variance = excluded.latency_variance,
                    unique_hashes_count = excluded.unique_hashes_count
            """, (plugin_id, total, avg_latency, variance, len(hashes)))
            conn.commit()

    def get_plugin_telemetry(self, plugin_id: str) -> Dict[str, Any]:
        """Trích xuất dữ liệu cô đọng cho AI Reasoning nạp vào Prompt Context"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM metrics_summary WHERE plugin_id = ?", (plugin_id,))
            summary = cursor.fetchone()
            
            # SỬA LỖI KIỂM TOÁN TẠI ĐÂY: Bổ sung chính xác response_hash và response_body vào câu lệnh SELECT
            cursor.execute("""
                SELECT payload, response_status, response_length, response_hash, response_body, latency, marker_hit 
                FROM interaction_logs WHERE plugin_id = ? ORDER BY id DESC LIMIT 5
            """, (plugin_id,))
            history = cursor.fetchall()
            
            return {
                "metrics": dict(summary) if summary else {},
                "recent_history": [dict(h) for h in history]
            }
