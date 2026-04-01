# ===== forensics_copilot.py =====
"""
ZeroCyber Digital Forensics Copilot
AI-powered forensic analysis assistant - works 100% offline.
Analyzes logs, memory patterns, network captures, and malware indicators.
"""

import os
import re
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Optional
from zerocyber_engine import ZeroCyberEngine


class ForensicsCopilot:
    """AI-assisted digital forensics analysis."""

    def __init__(self, engine: ZeroCyberEngine):
        self.engine = engine

    # ── Log Forensics ──────────────────────────────────────────
    def analyze_log_file(self, file_path: str) -> Dict:
        """Analyze a log file for security-relevant patterns."""
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            return {"error": str(e)}

        file_hash = hashlib.sha256(content.encode(errors="replace")).hexdigest()
        lines = content.split("\n")
        findings = {
            "file": file_path,
            "file_hash_sha256": file_hash,
            "total_lines": len(lines),
            "file_size_bytes": os.path.getsize(file_path),
            "analyzed_at": datetime.now().isoformat(),
            "suspicious_patterns": [],
            "ip_addresses": [],
            "timestamps": [],
            "error_patterns": [],
            "attack_indicators": []
        }

        # Extract patterns
        ip_pattern = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
        timestamp_pattern = re.compile(
            r"\b(\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2})\b"
        )

        attack_patterns = [
            (r"(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\s", "SQL Keywords"),
            (r"<script|javascript:|onerror\s*=", "XSS Indicators"),
            (r"\.\./\.\./|/etc/passwd", "Path Traversal"),
            (r"(cmd|powershell|bash)\s+.*(-enc|-e\s|/c\s)", "Command Execution"),
            (r"(failed|failure|denied|unauthorized|forbidden)", "Auth Failures"),
            (r"(error|exception|traceback|panic|fatal)", "Errors"),
            (r"(0x[0-9a-fA-F]{8,}|\\x[0-9a-fA-F]{2})", "Hex/Shellcode Patterns"),
            (r"base64[,:]|[A-Za-z0-9+/]{40,}={0,2}", "Base64 Data"),
            (r"(wget|curl|nc\s|netcat|reverse|shell)", "Tool Usage"),
            (r"(admin|root|superuser|administrator)\s*[:=]", "Privilege Indicators"),
        ]

        ips_found = set()
        for i, line in enumerate(lines):
            # IPs
            for match in ip_pattern.finditer(line):
                ips_found.add(match.group(1))

            # Timestamps
            for match in timestamp_pattern.finditer(line):
                if len(findings["timestamps"]) < 10:
                    findings["timestamps"].append(match.group(1))

            # Attack patterns
            line_lower = line.lower()
            for pattern, name in attack_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    if len(findings["attack_indicators"]) < 100:
                        findings["attack_indicators"].append({
                            "line_number": i + 1,
                            "pattern": name,
                            "content": line.strip()[:150]
                        })

        findings["ip_addresses"] = list(ips_found)[:50]
        findings["unique_ips"] = len(ips_found)

        # Summarize
        findings["summary"] = {
            "total_ips": len(ips_found),
            "total_attack_indicators": len(findings["attack_indicators"]),
            "indicator_types": list(set(
                i["pattern"] for i in findings["attack_indicators"]
            ))
        }

        # AI enrichment
        if self.engine.ollama_available and findings["attack_indicators"]:
            findings["ai_analysis"] = self._ai_log_analysis(findings)

        return findings

    # ── Network Capture Analysis ───────────────────────────────
    def analyze_network_data(self, data: str) -> Dict:
        """Analyze network capture data (text format)."""
        findings = {
            "analyzed_at": datetime.now().isoformat(),
            "connections": [],
            "dns_queries": [],
            "suspicious_traffic": [],
            "protocols": set()
        }

        lines = data.split("\n")
        for line in lines:
            # DNS queries
            if "DNS" in line.upper() or "query" in line.lower():
                findings["dns_queries"].append(line.strip()[:200])

            # HTTP requests
            if any(m in line for m in ["GET ", "POST ", "PUT ", "DELETE "]):
                findings["connections"].append(line.strip()[:200])

            # Suspicious patterns
            if any(s in line.lower() for s in [
                "reverse", "shell", "c2", "beacon", "exfil",
                "mimikatz", "bloodhound", "cobalt"
            ]):
                findings["suspicious_traffic"].append(line.strip()[:200])

        findings["protocols"] = list(findings["protocols"])

        if self.engine.ollama_available and (findings["suspicious_traffic"] or findings["connections"]):
            findings["ai_analysis"] = self._ai_network_analysis(findings)

        return findings

    # ── File Hash Analysis ─────────────────────────────────────
    def analyze_file(self, file_path: str) -> Dict:
        """Compute hashes and analyze a suspicious file."""
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}

        stat = os.stat(file_path)
        with open(file_path, "rb") as f:
            content = f.read()

        md5 = hashlib.md5(content).hexdigest()
        sha1 = hashlib.sha1(content).hexdigest()
        sha256 = hashlib.sha256(content).hexdigest()

        # Entropy calculation
        entropy = self._calculate_entropy(content)

        # String extraction (printable)
        strings = self._extract_strings(content)

        # Suspicious string indicators
        suspicious_strings = []
        indicators = [
            "http://", "https://", "cmd.exe", "powershell",
            "/bin/sh", "/bin/bash", "CreateProcess", "VirtualAlloc",
            "WriteProcessMemory", "LoadLibrary", "GetProcAddress",
            "socket", "connect", "recv", "send", "WSAStartup",
            "RegSetValueEx", "CreateService", "HKEY_",
            "password", "credential", "token", "secret",
        ]
        for s in strings:
            for ind in indicators:
                if ind.lower() in s.lower():
                    suspicious_strings.append({"string": s[:100], "indicator": ind})
                    break

        result = {
            "file": file_path,
            "file_name": os.path.basename(file_path),
            "file_size": stat.st_size,
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "hashes": {"md5": md5, "sha1": sha1, "sha256": sha256},
            "entropy": round(entropy, 4),
            "is_high_entropy": entropy > 7.0,
            "total_strings": len(strings),
            "suspicious_strings": suspicious_strings[:30],
            "analyzed_at": datetime.now().isoformat()
        }

        # AI analysis
        if self.engine.ollama_available:
            result["ai_analysis"] = self._ai_file_analysis(result)

        return result

    # ── Incident Timeline Builder ──────────────────────────────
    def build_incident_timeline(self, events: List[Dict]) -> Dict:
        """Build a forensic timeline from multiple evidence sources."""
        if not events:
            return {"timeline": [], "analysis": "No events provided"}

        sorted_events = sorted(events, key=lambda e: e.get("timestamp", ""))

        timeline = []
        for i, event in enumerate(sorted_events):
            timeline.append({
                "sequence": i + 1,
                "timestamp": event.get("timestamp", "unknown"),
                "source": event.get("source", "unknown"),
                "event_type": event.get("type", "unknown"),
                "description": event.get("description", ""),
                "severity": event.get("severity", "INFO"),
                "evidence": event.get("evidence", "")
            })

        result = {
            "timeline": timeline,
            "event_count": len(timeline),
            "time_span": {
                "start": timeline[0]["timestamp"] if timeline else None,
                "end": timeline[-1]["timestamp"] if timeline else None
            },
            "generated_at": datetime.now().isoformat()
        }

        if self.engine.ollama_available:
            result["ai_analysis"] = self._ai_timeline_analysis(timeline)

        return result

    # ── Interactive Chat ───────────────────────────────────────
    def chat(self, question: str, context: str = "") -> str:
        """Chat with the forensics copilot about a case."""
        system = (
            "You are ZeroCyber Forensics Copilot, an expert in digital forensics "
            "and incident response. You help analysts investigate security incidents, "
            "analyze evidence, build timelines, and write reports. "
            "Always be precise and cite specific evidence when making conclusions."
        )
        if context:
            system += f"\n\nCase Context:\n{context}"
        return self.engine.chat(question, system)

    # ── AI Helpers ─────────────────────────────────────────────
    def _ai_log_analysis(self, findings: Dict) -> str:
        indicators = "\n".join([
            f"  Line {i['line_number']}: [{i['pattern']}] {i['content'][:80]}"
            for i in findings["attack_indicators"][:20]
        ])
        prompt = (
            "You are ZeroCyber Forensics AI. Analyze these log indicators.\n"
            f"File: {findings['file']}\n"
            f"Total lines: {findings['total_lines']}\n"
            f"Unique IPs: {findings['unique_ips']}\n\n"
            f"Attack Indicators:\n{indicators}\n\n"
            "Provide a forensic analysis: what happened, attack timeline, "
            "and recommended investigation steps."
        )
        return self.engine._ask_model(prompt, timeout=120)

    def _ai_network_analysis(self, findings: Dict) -> str:
        traffic = "\n".join(findings["suspicious_traffic"][:10])
        conns = "\n".join(findings["connections"][:10])
        prompt = (
            "You are ZeroCyber Network Forensics AI. Analyze this traffic.\n\n"
            f"Suspicious Traffic:\n{traffic}\n\n"
            f"HTTP Connections:\n{conns}\n\n"
            "Identify potential threats, C2 communication, and data exfiltration."
        )
        return self.engine._ask_model(prompt, timeout=120)

    def _ai_file_analysis(self, result: Dict) -> str:
        susp = "\n".join([
            f"  {s['indicator']}: {s['string']}"
            for s in result["suspicious_strings"][:15]
        ])
        prompt = (
            "You are ZeroCyber Malware Analysis AI. Analyze this file.\n\n"
            f"File: {result['file_name']}\n"
            f"Size: {result['file_size']} bytes\n"
            f"Entropy: {result['entropy']} {'(HIGH - likely packed/encrypted)' if result['is_high_entropy'] else '(normal)'}\n"
            f"SHA256: {result['hashes']['sha256']}\n\n"
            f"Suspicious Strings:\n{susp}\n\n"
            "Assess if this file is malicious, its potential purpose, and recommended actions."
        )
        return self.engine._ask_model(prompt, timeout=120)

    def _ai_timeline_analysis(self, timeline: List[Dict]) -> str:
        events = "\n".join([
            f"  [{e['sequence']}] {e['timestamp']} | {e['event_type']} | {e['description'][:60]}"
            for e in timeline[:20]
        ])
        prompt = (
            "You are ZeroCyber Incident Response AI. Analyze this forensic timeline.\n\n"
            f"Events:\n{events}\n\n"
            "Provide: 1) Attack narrative 2) Kill chain mapping "
            "3) Indicators of Compromise 4) Remediation steps"
        )
        return self.engine._ask_model(prompt, timeout=120)

    # ── Utility ────────────────────────────────────────────────
    def _calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        import math
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        length = len(data)
        entropy = 0.0
        for f in freq:
            if f > 0:
                p = f / length
                entropy -= p * math.log2(p)
        return entropy

    def _extract_strings(self, data: bytes, min_length: int = 6) -> List[str]:
        pattern = rb"[\x20-\x7E]{%d,}" % min_length
        return [s.decode("ascii", errors="ignore") for s in re.findall(pattern, data)][:500]
