# ===== narrative_generator.py =====
"""
ZeroCyber Attack Narrative Generator
Converts scattered security events into a coherent human-readable attack story.
Unique feature: no other product does this.
"""

import json
from datetime import datetime
from typing import Dict, List
from zerocyber_engine import ZeroCyberEngine


class AttackNarrativeGenerator:
    """Builds attack stories from security events using ZeroCyber-SLM."""

    def __init__(self, engine: ZeroCyberEngine):
        self.engine = engine

    def build_narrative(self, events: List[Dict], source_ip: str) -> str:
        """Build a complete attack narrative from a sequence of events."""
        if not events:
            return "No events to narrate."

        # Build timeline
        timeline = self._build_timeline(events)

        # If AI available, generate rich narrative
        if self.engine.ollama_available:
            return self._ai_narrative(timeline, source_ip)

        # Fallback: rule-based narrative
        return self._rule_based_narrative(timeline, source_ip)

    def _build_timeline(self, events: List[Dict]) -> List[Dict]:
        """Sort and structure events chronologically."""
        sorted_events = sorted(events, key=lambda e: e.get("timestamp", ""))
        timeline = []
        for i, event in enumerate(sorted_events):
            timeline.append({
                "sequence": i + 1,
                "timestamp": event.get("timestamp", "unknown"),
                "attack_type": event.get("attack_type", "Unknown"),
                "classification": event.get("classification", "LOW"),
                "confidence": event.get("confidence", 0.5),
                "action": event.get("action", "LOG"),
                "signature": event.get("signature", ""),
                "method": event.get("context", {}).get("method", ""),
                "path": event.get("context", {}).get("path", ""),
                "evasion": event.get("evasion", {}).get("techniques", [])
            })
        return timeline

    def _ai_narrative(self, timeline: List[Dict], source_ip: str) -> str:
        """Generate rich narrative using ZeroCyber-SLM."""
        events_summary = "\n".join([
            f"  [{e['sequence']}] {e['timestamp']} | {e['attack_type']} ({e['classification']}) | "
            f"{e['method']} {e['path']} | Signature: {e['signature'][:60]} | "
            f"Evasion: {', '.join(e['evasion']) if e['evasion'] else 'None'}"
            for e in timeline
        ])

        prompt = (
            "You are ZeroCyber, a cybersecurity AI. Generate a detailed attack narrative report.\n\n"
            "Write a professional incident report that tells the STORY of this attack "
            "as if narrating events to a SOC analyst. Include:\n"
            "1. Executive Summary (2-3 sentences)\n"
            "2. Attack Timeline (describe each phase in natural language)\n"
            "3. Attacker Behavior Analysis (what tactics they used and why)\n"
            "4. Evasion Techniques Used (if any)\n"
            "5. Risk Assessment\n"
            "6. Recommended Immediate Actions\n\n"
            f"Source IP: {source_ip}\n"
            f"Total Events: {len(timeline)}\n"
            f"Time Span: {timeline[0]['timestamp']} to {timeline[-1]['timestamp']}\n\n"
            f"Events:\n{events_summary}\n\n"
            "Write the narrative report:"
        )

        narrative = self.engine._ask_model(prompt, timeout=180)
        if narrative and len(narrative) > 50:
            return narrative
        return self._rule_based_narrative(timeline, source_ip)

    def _rule_based_narrative(self, timeline: List[Dict], source_ip: str) -> str:
        """Generate narrative without AI (fallback)."""
        n = len(timeline)
        first = timeline[0]
        last = timeline[-1]

        # Determine attack phases
        attack_types = [e["attack_type"] for e in timeline]
        unique_types = list(dict.fromkeys(attack_types))
        max_severity = max(
            timeline,
            key=lambda e: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(e["classification"], 0)
        )
        evasion_used = any(e["evasion"] for e in timeline)

        # Build narrative
        lines = []
        lines.append("=" * 70)
        lines.append("ZEROCYBER ATTACK NARRATIVE REPORT")
        lines.append("=" * 70)
        lines.append("")

        # Executive Summary
        lines.append("[EXECUTIVE SUMMARY]")
        lines.append(
            f"An attacker from IP {source_ip} conducted {n} operations between "
            f"{first['timestamp']} and {last['timestamp']}. "
            f"The attack involved {len(unique_types)} distinct attack vector(s): "
            f"{', '.join(unique_types)}. "
            f"Maximum threat level reached: {max_severity['classification']}."
        )
        if evasion_used:
            all_evasions = set()
            for e in timeline:
                all_evasions.update(e["evasion"])
            lines.append(
                f"The attacker employed evasion techniques: {', '.join(all_evasions)}."
            )
        lines.append("")

        # Timeline
        lines.append("[ATTACK TIMELINE]")
        for e in timeline:
            phase_desc = self._describe_phase(e, timeline)
            lines.append(f"  [{e['sequence']}] {e['timestamp']}")
            lines.append(f"      Attack: {e['attack_type']} | Severity: {e['classification']}")
            lines.append(f"      Target: {e['method']} {e['path']}")
            lines.append(f"      Signature: {e['signature'][:60]}")
            lines.append(f"      Analysis: {phase_desc}")
            lines.append("")

        # Behavior Analysis
        lines.append("[ATTACKER BEHAVIOR ANALYSIS]")
        if n == 1:
            lines.append("  - Single probe detected. Likely automated scanner or initial reconnaissance.")
        elif n <= 3:
            lines.append("  - Limited probing detected. Attacker is testing attack surface.")
        elif n <= 7:
            lines.append("  - Sustained attack campaign. Attacker is actively exploiting vulnerabilities.")
        else:
            lines.append("  - Aggressive multi-vector assault. Highly determined attacker.")

        if len(unique_types) > 1:
            lines.append(f"  - Attacker switched between {len(unique_types)} attack vectors, "
                        "indicating adaptability and knowledge of multiple exploitation techniques.")
        if evasion_used:
            lines.append("  - Use of evasion techniques suggests sophisticated adversary.")
        lines.append("")

        # Risk Assessment
        lines.append("[RISK ASSESSMENT]")
        risk_score = min(10, n * 1.5 + (3 if evasion_used else 0) +
                        {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}.get(max_severity["classification"], 0))
        lines.append(f"  Overall Risk Score: {risk_score:.1f}/10")
        lines.append(f"  Attack Sophistication: {'HIGH' if evasion_used else 'MEDIUM' if n > 3 else 'LOW'}")
        lines.append(f"  Persistence Level: {'HIGH' if n > 5 else 'MEDIUM' if n > 2 else 'LOW'}")
        lines.append("")

        # Recommendations
        lines.append("[RECOMMENDED ACTIONS]")
        if max_severity["classification"] in ("CRITICAL", "HIGH"):
            lines.append(f"  1. IMMEDIATELY block IP {source_ip}")
            lines.append("  2. Investigate affected systems for compromise")
            lines.append("  3. Review firewall rules and WAF configuration")
            lines.append("  4. Check for data exfiltration indicators")
        else:
            lines.append(f"  1. Monitor IP {source_ip} for continued activity")
            lines.append("  2. Review application input validation")
            lines.append("  3. Update detection signatures")
        lines.append("")
        lines.append("=" * 70)
        lines.append(f"Generated by ZeroCyber-SLM | {datetime.now().isoformat()}")
        lines.append("=" * 70)

        return "\n".join(lines)

    def _describe_phase(self, event: Dict, all_events: List[Dict]) -> str:
        """Describe what happened in this phase of the attack."""
        seq = event["sequence"]
        total = len(all_events)
        atype = event["attack_type"]

        if seq == 1:
            return f"Initial contact - attacker begins with {atype} probe."
        if seq == total:
            return f"Final observed action - {atype} attempt {'with evasion' if event['evasion'] else 'direct'}."

        prev = all_events[seq - 2] if seq > 1 else None
        if prev and prev["attack_type"] != atype:
            return f"Attacker pivoted from {prev['attack_type']} to {atype}."
        return f"Continued {atype} exploitation attempt."

    def generate_executive_brief(self, events: List[Dict], source_ip: str) -> Dict:
        """Generate a structured executive brief for API consumption."""
        if not events:
            return {"summary": "No activity", "risk": "NONE"}

        timeline = self._build_timeline(events)
        attack_types = list(set(e["attack_type"] for e in timeline))
        max_class = max(
            ["LOW"] + [e["classification"] for e in timeline],
            key=lambda c: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(c, 0)
        )
        evasion_count = sum(1 for e in timeline if e["evasion"])

        return {
            "source_ip": source_ip,
            "event_count": len(events),
            "time_span": {
                "first": timeline[0]["timestamp"],
                "last": timeline[-1]["timestamp"]
            },
            "attack_vectors": attack_types,
            "max_severity": max_class,
            "evasion_attempts": evasion_count,
            "risk_score": round(min(10, len(events) * 1.5 + evasion_count * 2), 1),
            "recommended_action": "BLOCK" if max_class in ("CRITICAL", "HIGH") else "MONITOR"
        }
