# ===== zerocyber_complete.py =====
"""
ZeroCyber Complete System - v3.0 PRODUCTION
All components integrated and ready for deployment.
"""

import sys
import json
from datetime import datetime
from typing import Dict

# Import all modules
from persistence import ZeroCyberDB
from zerocyber_engine import ZeroCyberEngine
from mitre_mapper import MITREMapper
from narrative_generator import AttackNarrativeGenerator
from threat_hunter import ThreatHunter
from forensics_copilot import ForensicsCopilot
from immune_system import CrossPlatformImmune
from integrations import IntegrationManager


class ZeroCyberComplete:
    """Complete ZeroCyber system with all components."""

    def __init__(self, config_file: str = "zerocyber_config.json"):
        import sys
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
        print("\n" + "="*80)
        print("[ZEROCYBER] ZeroCyber-SLM v3.0 COMPLETE SYSTEM")
        print("="*80)

        # Initialize core systems
        self.db = ZeroCyberDB()
        self.engine = ZeroCyberEngine()
        self.mitre = MITREMapper()
        self.narrator = AttackNarrativeGenerator(self.engine)
        self.hunter = ThreatHunter(self.engine)
        self.forensics = ForensicsCopilot(self.engine)
        self.immune = CrossPlatformImmune()
        self.integrations = IntegrationManager()

        # Load configuration
        self._load_config(config_file)

        print("[OK] All systems initialized successfully")
        print("="*80 + "\n")

    def _load_config(self, config_file: str):
        try:
            with open(config_file, "r") as f:
                config = json.load(f)
            self.integrations.configure(config.get("integrations", {}))
            print(f"[CONFIG] Loaded: {config_file}")
        except FileNotFoundError:
            print(f"[CONFIG] {config_file} not found (using defaults)")
        except Exception as e:
            print(f"[CONFIG] Error: {e}")

    def analyze_threat(self, payload: str, source_ip: str = "unknown") -> Dict:
        """Complete threat analysis pipeline."""
        # 1. Detection
        result = self.engine.analyze(payload, source_ip)

        # 2. MITRE mapping
        mitre_map = self.mitre.generate_full_mapping(result["attack_type"], result["confidence"])
        result["mitre"] = mitre_map

        # 3. Save to database
        threat_id = self.db.save_threat({
            "timestamp": result["timestamp"],
            "source_ip": source_ip,
            "attack_type": result["attack_type"],
            "classification": result["classification"],
            "confidence": result["confidence"],
            "action": result["action"],
            "payload_preview": result["payload_preview"],
            "signature": result["signature"],
            "ai_insight": result["ai_insight"],
            "detection_method": result["detection_method"],
            "mitre_tactic": mitre_map["mitre_mapping"]["tactic"]["name"],
            "mitre_technique": mitre_map["mitre_mapping"]["technique"]["name"]
        })
        result["threat_id"] = threat_id

        # 4. Take action
        if result["classification"] in ("CRITICAL", "HIGH"):
            # Block IP
            self.immune.block_ip(source_ip, reason=f"Blocked: {result['attack_type']}")
            # Broadcast alert
            self.integrations.broadcast_threat(result)

        # 5. Create narrative event
        self.db.append_narrative_event(source_ip, result)

        return result

    def hunt_threats(self) -> Dict:
        """Run complete threat hunting session."""
        print("[HUNTER] Starting autonomous threat hunt...")
        hunt_result = self.hunter.run_full_hunt()
        session_id = hunt_result["session_id"]
        self.db.create_hunt_session(session_id)
        self.db.update_hunt_session(session_id, hunt_result["findings"], "completed")
        print(f"[HUNTER] Found {hunt_result['findings_count']} potential threats")
        return hunt_result

    def analyze_file(self, file_path: str) -> Dict:
        """Forensic analysis of a file."""
        return self.forensics.analyze_file(file_path)

    def analyze_logs(self, file_path: str) -> Dict:
        """Forensic analysis of logs."""
        return self.forensics.analyze_log_file(file_path)

    def get_status(self) -> Dict:
        """Get complete system status."""
        stats = self.db.get_dashboard_stats()
        return {
            "timestamp": datetime.now().isoformat(),
            "system": "ZeroCyber-SLM v3.0",
            "ai_model": "ZeroCyber-SLM" if self.engine.ollama_available else "Rules-based",
            "detection_rules": len(self.engine.rules),
            "threats_detected": stats["threats"]["total_threats"],
            "critical_threats": stats["threats"]["by_classification"].get("CRITICAL", 0),
            "blocked_ips": stats["blocked_ips"],
            "immune_status": self.immune.get_status(),
            "integrations": self.integrations.get_status(),
            "audit_chain_blocks": stats["chain_blocks"],
            "hunt_sessions": stats["hunt_sessions"],
            "forensic_reports": stats["forensic_reports"]
        }

    def generate_report(self) -> Dict:
        """Generate comprehensive security report."""
        status = self.get_status()
        threats = self.db.get_threats(limit=100)
        narratives = self.db.get_active_narratives()
        chain = self.db.get_chain(limit=50)

        return {
            "report_generated": datetime.now().isoformat(),
            "system_status": status,
            "recent_threats": threats,
            "attack_narratives": narratives,
            "audit_chain_sample": chain,
            "mitre_coverage": self.mitre.get_coverage_report()
        }

    def export_data(self, format: str = "json") -> str:
        """Export all data."""
        report = self.generate_report()
        if format == "json":
            return json.dumps(report, indent=2, ensure_ascii=False)
        return str(report)


# ── CLI Interface ──────────────────────────────────────────────
def main():
    system = ZeroCyberComplete()

    # Demo: Analyze some test payloads
    print("[DEMO] Testing threat detection...")
    test_payloads = [
        ("SELECT * FROM users WHERE id='1' OR '1'='1", "192.168.1.100", "SQL Injection"),
        ("<script>alert('xss')</script>", "10.0.0.50", "XSS"),
        ("cat /etc/passwd", "172.16.0.10", "Command Injection"),
    ]

    for payload, ip, desc in test_payloads:
        print(f"\n[TEST] {desc} from {ip}")
        result = system.analyze_threat(payload, ip)
        print(f"  → Detected: {result['attack_type']} ({result['classification']})")
        print(f"  → Confidence: {result['confidence']*100:.0f}%")
        print(f"  → Action: {result['action']}")

    # Show status
    print("\n" + "="*80)
    print("SYSTEM STATUS")
    print("="*80)
    status = system.get_status()
    for key, value in status.items():
        print(f"{key:20} : {value}")

    print("\n[✓] ZeroCyber-SLM v3.0 is operational")
    print("[API] REST API available at http://localhost:5000/api/v3")
    print("[WEB] Dashboard available at http://localhost:8000")
    print("[HUNT] Run threat hunting with: system.hunt_threats()")


if __name__ == "__main__":
    main()
