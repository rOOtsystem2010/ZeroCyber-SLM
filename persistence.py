# ===== persistence.py =====
"""
ZeroCyber Persistence Layer - SQLite Database
All threat data, audit chains, and forensics persist across restarts.
"""

import sqlite3
import json
import threading
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Any


class ZeroCyberDB:
    """Thread-safe SQLite persistence for ZeroCyber system."""

    def __init__(self, db_path: str = "zerocyber_production.db"):
        self.db_path = db_path
        self._local = threading.local()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path, timeout=30)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
        return self._local.conn

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript("""
            -- Threat events table
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                classification TEXT NOT NULL,
                confidence REAL NOT NULL,
                action_taken TEXT NOT NULL,
                payload_preview TEXT,
                signature TEXT,
                ai_insight TEXT,
                detection_method TEXT,
                mitre_tactic TEXT,
                mitre_technique TEXT,
                narrative TEXT,
                processing_time_ms REAL,
                raw_payload_hash TEXT
            );

            -- Blockchain audit chain
            CREATE TABLE IF NOT EXISTS audit_chain (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                block_index INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                data_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                block_hash TEXT NOT NULL,
                nonce INTEGER DEFAULT 0,
                merkle_root TEXT,
                is_verified INTEGER DEFAULT 1
            );

            -- Blocked IPs
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                reason TEXT,
                blocked_at TEXT NOT NULL,
                expires_at TEXT,
                block_count INTEGER DEFAULT 1,
                is_active INTEGER DEFAULT 1
            );

            -- Forensic reports
            CREATE TABLE IF NOT EXISTS forensic_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                report_type TEXT NOT NULL,
                title TEXT,
                findings_json TEXT,
                severity TEXT,
                status TEXT DEFAULT 'open'
            );

            -- Threat hunting sessions
            CREATE TABLE IF NOT EXISTS hunt_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                findings_count INTEGER DEFAULT 0,
                findings_json TEXT,
                status TEXT DEFAULT 'running'
            );

            -- System metrics
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                total_requests INTEGER,
                total_threats INTEGER,
                total_blocked INTEGER,
                avg_confidence REAL,
                avg_processing_ms REAL,
                uptime_seconds REAL
            );

            -- API keys
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_hash TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                permissions TEXT DEFAULT 'read',
                created_at TEXT NOT NULL,
                last_used TEXT,
                is_active INTEGER DEFAULT 1
            );

            -- Attack narratives
            CREATE TABLE IF NOT EXISTS attack_narratives (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT NOT NULL,
                started_at TEXT,
                last_event_at TEXT,
                event_count INTEGER DEFAULT 0,
                narrative_text TEXT,
                events_json TEXT,
                threat_level TEXT DEFAULT 'LOW',
                is_active INTEGER DEFAULT 1
            );

            -- Indexes
            CREATE INDEX IF NOT EXISTS idx_threats_ip ON threats(source_ip);
            CREATE INDEX IF NOT EXISTS idx_threats_type ON threats(attack_type);
            CREATE INDEX IF NOT EXISTS idx_threats_time ON threats(timestamp);
            CREATE INDEX IF NOT EXISTS idx_threats_class ON threats(classification);
            CREATE INDEX IF NOT EXISTS idx_blocked_ip ON blocked_ips(ip_address);
            CREATE INDEX IF NOT EXISTS idx_audit_hash ON audit_chain(block_hash);
            CREATE INDEX IF NOT EXISTS idx_narratives_ip ON attack_narratives(source_ip);
        """)
        conn.commit()

    # ── Threat Events ──────────────────────────────────────────
    def save_threat(self, threat: Dict) -> int:
        conn = self._get_conn()
        cur = conn.execute("""
            INSERT INTO threats (
                timestamp, source_ip, attack_type, classification, confidence,
                action_taken, payload_preview, signature, ai_insight,
                detection_method, mitre_tactic, mitre_technique, narrative,
                processing_time_ms, raw_payload_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            threat.get("timestamp", datetime.now().isoformat()),
            threat.get("source_ip", "unknown"),
            threat.get("attack_type", "Unknown"),
            threat.get("classification", "LOW"),
            threat.get("confidence", 0.5),
            threat.get("action", "LOG"),
            threat.get("payload_preview", ""),
            threat.get("signature", ""),
            threat.get("ai_insight", ""),
            threat.get("detection_method", "rule-based"),
            threat.get("mitre_tactic", ""),
            threat.get("mitre_technique", ""),
            threat.get("narrative", ""),
            threat.get("processing_time_ms", 0),
            threat.get("raw_payload_hash", "")
        ))
        conn.commit()
        return cur.lastrowid

    def get_threats(self, limit: int = 100, offset: int = 0,
                    ip: Optional[str] = None,
                    attack_type: Optional[str] = None,
                    classification: Optional[str] = None) -> List[Dict]:
        conn = self._get_conn()
        query = "SELECT * FROM threats WHERE 1=1"
        params = []
        if ip:
            query += " AND source_ip = ?"
            params.append(ip)
        if attack_type:
            query += " AND attack_type = ?"
            params.append(attack_type)
        if classification:
            query += " AND classification = ?"
            params.append(classification)
        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_threat_stats(self) -> Dict:
        conn = self._get_conn()
        total = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
        by_type = conn.execute(
            "SELECT attack_type, COUNT(*) as cnt FROM threats GROUP BY attack_type ORDER BY cnt DESC"
        ).fetchall()
        by_class = conn.execute(
            "SELECT classification, COUNT(*) as cnt FROM threats GROUP BY classification ORDER BY cnt DESC"
        ).fetchall()
        by_ip = conn.execute(
            "SELECT source_ip, COUNT(*) as cnt FROM threats GROUP BY source_ip ORDER BY cnt DESC LIMIT 20"
        ).fetchall()
        avg_conf = conn.execute(
            "SELECT AVG(confidence) FROM threats"
        ).fetchone()[0] or 0
        return {
            "total_threats": total,
            "by_type": {r["attack_type"]: r["cnt"] for r in by_type},
            "by_classification": {r["classification"]: r["cnt"] for r in by_class},
            "top_attackers": {r["source_ip"]: r["cnt"] for r in by_ip},
            "avg_confidence": round(avg_conf, 3)
        }

    # ── Blocked IPs ────────────────────────────────────────────
    def block_ip(self, ip: str, reason: str, expires_at: Optional[str] = None) -> int:
        conn = self._get_conn()
        existing = conn.execute(
            "SELECT id, block_count FROM blocked_ips WHERE ip_address = ?", (ip,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE blocked_ips SET is_active=1, block_count=?, reason=?, blocked_at=?, expires_at=? WHERE ip_address=?",
                (existing["block_count"] + 1, reason, datetime.now().isoformat(), expires_at, ip)
            )
            conn.commit()
            return existing["id"]
        cur = conn.execute(
            "INSERT INTO blocked_ips (ip_address, reason, blocked_at, expires_at) VALUES (?, ?, ?, ?)",
            (ip, reason, datetime.now().isoformat(), expires_at)
        )
        conn.commit()
        return cur.lastrowid

    def is_blocked(self, ip: str) -> bool:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT is_active, expires_at FROM blocked_ips WHERE ip_address = ? AND is_active = 1",
            (ip,)
        ).fetchone()
        if not row:
            return False
        if row["expires_at"]:
            if datetime.fromisoformat(row["expires_at"]) < datetime.now():
                conn.execute("UPDATE blocked_ips SET is_active=0 WHERE ip_address=?", (ip,))
                conn.commit()
                return False
        return True

    def get_blocked_ips(self) -> List[Dict]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM blocked_ips WHERE is_active = 1 ORDER BY blocked_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Audit Chain ────────────────────────────────────────────
    def save_block(self, block: Dict) -> int:
        conn = self._get_conn()
        cur = conn.execute(
            "INSERT INTO audit_chain (block_index, timestamp, data_json, previous_hash, block_hash, nonce, merkle_root) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                block.get("index", 0),
                block.get("timestamp", datetime.now().isoformat()),
                json.dumps(block.get("data", {}), ensure_ascii=False),
                block.get("previous_hash", ""),
                block.get("hash", ""),
                block.get("nonce", 0),
                block.get("merkle_root", "")
            )
        )
        conn.commit()
        return cur.lastrowid

    def get_chain(self, limit: int = 100) -> List[Dict]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM audit_chain ORDER BY block_index DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def verify_chain_integrity(self) -> Dict:
        conn = self._get_conn()
        blocks = conn.execute("SELECT * FROM audit_chain ORDER BY block_index ASC").fetchall()
        if not blocks:
            return {"valid": True, "blocks": 0, "issues": []}
        issues = []
        for i in range(1, len(blocks)):
            if blocks[i]["previous_hash"] != blocks[i - 1]["block_hash"]:
                issues.append(f"Block {blocks[i]['block_index']}: hash chain broken")
        return {
            "valid": len(issues) == 0,
            "blocks": len(blocks),
            "issues": issues
        }

    # ── Attack Narratives ──────────────────────────────────────
    def get_or_create_narrative(self, source_ip: str) -> Dict:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM attack_narratives WHERE source_ip = ? AND is_active = 1",
            (source_ip,)
        ).fetchone()
        if row:
            return dict(row)
        cur = conn.execute(
            "INSERT INTO attack_narratives (source_ip, started_at, events_json) VALUES (?, ?, ?)",
            (source_ip, datetime.now().isoformat(), "[]")
        )
        conn.commit()
        return dict(conn.execute("SELECT * FROM attack_narratives WHERE id = ?", (cur.lastrowid,)).fetchone())

    def append_narrative_event(self, source_ip: str, event: Dict):
        conn = self._get_conn()
        narrative = self.get_or_create_narrative(source_ip)
        events = json.loads(narrative["events_json"] or "[]")
        events.append(event)
        threat_level = self._calculate_narrative_threat(events)
        conn.execute(
            "UPDATE attack_narratives SET last_event_at=?, event_count=?, events_json=?, threat_level=? WHERE id=?",
            (datetime.now().isoformat(), len(events), json.dumps(events, ensure_ascii=False), threat_level, narrative["id"])
        )
        conn.commit()

    def _calculate_narrative_threat(self, events: List[Dict]) -> str:
        if len(events) >= 10:
            return "CRITICAL"
        if len(events) >= 5:
            return "HIGH"
        if len(events) >= 3:
            return "MEDIUM"
        return "LOW"

    def update_narrative_text(self, source_ip: str, text: str):
        conn = self._get_conn()
        conn.execute(
            "UPDATE attack_narratives SET narrative_text=? WHERE source_ip=? AND is_active=1",
            (text, source_ip)
        )
        conn.commit()

    def get_active_narratives(self) -> List[Dict]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM attack_narratives WHERE is_active = 1 ORDER BY last_event_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Forensic Reports ───────────────────────────────────────
    def save_forensic_report(self, report: Dict) -> int:
        conn = self._get_conn()
        cur = conn.execute(
            "INSERT INTO forensic_reports (report_id, timestamp, report_type, title, findings_json, severity) VALUES (?, ?, ?, ?, ?, ?)",
            (
                report.get("report_id", f"FR-{datetime.now().strftime('%Y%m%d%H%M%S')}"),
                datetime.now().isoformat(),
                report.get("type", "general"),
                report.get("title", "Forensic Report"),
                json.dumps(report.get("findings", {}), ensure_ascii=False),
                report.get("severity", "MEDIUM")
            )
        )
        conn.commit()
        return cur.lastrowid

    def get_forensic_reports(self, limit: int = 50) -> List[Dict]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM forensic_reports ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Hunt Sessions ──────────────────────────────────────────
    def create_hunt_session(self, session_id: str) -> int:
        conn = self._get_conn()
        cur = conn.execute(
            "INSERT INTO hunt_sessions (session_id, started_at) VALUES (?, ?)",
            (session_id, datetime.now().isoformat())
        )
        conn.commit()
        return cur.lastrowid

    def update_hunt_session(self, session_id: str, findings: List[Dict], status: str = "completed"):
        conn = self._get_conn()
        conn.execute(
            "UPDATE hunt_sessions SET completed_at=?, findings_count=?, findings_json=?, status=? WHERE session_id=?",
            (datetime.now().isoformat(), len(findings), json.dumps(findings, ensure_ascii=False), status, session_id)
        )
        conn.commit()

    # ── Metrics ────────────────────────────────────────────────
    def save_metrics(self, metrics: Dict):
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO metrics (timestamp, total_requests, total_threats, total_blocked, avg_confidence, avg_processing_ms, uptime_seconds) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                datetime.now().isoformat(),
                metrics.get("total_requests", 0),
                metrics.get("total_threats", 0),
                metrics.get("total_blocked", 0),
                metrics.get("avg_confidence", 0),
                metrics.get("avg_processing_ms", 0),
                metrics.get("uptime_seconds", 0)
            )
        )
        conn.commit()

    # ── API Keys ───────────────────────────────────────────────
    def create_api_key(self, raw_key: str, name: str, permissions: str = "read") -> int:
        conn = self._get_conn()
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        cur = conn.execute(
            "INSERT INTO api_keys (key_hash, name, permissions, created_at) VALUES (?, ?, ?, ?)",
            (key_hash, name, permissions, datetime.now().isoformat())
        )
        conn.commit()
        return cur.lastrowid

    def validate_api_key(self, raw_key: str) -> Optional[Dict]:
        conn = self._get_conn()
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        row = conn.execute(
            "SELECT * FROM api_keys WHERE key_hash = ? AND is_active = 1", (key_hash,)
        ).fetchone()
        if row:
            conn.execute("UPDATE api_keys SET last_used=? WHERE id=?", (datetime.now().isoformat(), row["id"]))
            conn.commit()
            return dict(row)
        return None

    # ── Dashboard Stats ────────────────────────────────────────
    def get_dashboard_stats(self) -> Dict:
        conn = self._get_conn()
        threat_stats = self.get_threat_stats()
        blocked = conn.execute("SELECT COUNT(*) FROM blocked_ips WHERE is_active=1").fetchone()[0]
        chain_len = conn.execute("SELECT COUNT(*) FROM audit_chain").fetchone()[0]
        hunts = conn.execute("SELECT COUNT(*) FROM hunt_sessions").fetchone()[0]
        forensics = conn.execute("SELECT COUNT(*) FROM forensic_reports").fetchone()[0]
        recent = self.get_threats(limit=10)
        return {
            "threats": threat_stats,
            "blocked_ips": blocked,
            "chain_blocks": chain_len,
            "hunt_sessions": hunts,
            "forensic_reports": forensics,
            "recent_threats": recent
        }
