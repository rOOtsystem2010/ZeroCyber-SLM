# ===== zerocyber_engine.py =====
"""
ZeroCyber AI Engine - Production v3.0
Hybrid detection: Fast rule-based + Deep AI analysis via Ollama ZeroCyber-SLM
"""

import json
import re
import hashlib
import requests
from datetime import datetime
from typing import Dict, Optional, Tuple, List

OLLAMA_URL = "http://localhost:11434"
OLLAMA_MODEL = "ZeroCyber-SLM"


class ZeroCyberEngine:
    """Core detection engine: Rules (fast) + ZeroCyber-SLM AI (deep)."""

    def __init__(self):
        self.ollama_available = self._check_ollama()
        self._build_rules()
        if self.ollama_available:
            print("[ENGINE] ZeroCyber-SLM model connected via Ollama")
        else:
            print("[ENGINE] Ollama unavailable - rule-based mode only")
        print(f"[ENGINE] {len(self.rules)} detection rules loaded")

    # ── Ollama connectivity ────────────────────────────────────
    def _check_ollama(self) -> bool:
        try:
            r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
            models = [m["name"].lower() for m in r.json().get("models", [])]
            return any("zerocyber" in m for m in models)
        except Exception:
            return False

    def _ask_model(self, prompt: str, timeout: int = 120) -> str:
        try:
            r = requests.post(
                f"{OLLAMA_URL}/api/generate",
                json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False,
                      "options": {"temperature": 0.2, "num_ctx": 4096}},
                timeout=timeout
            )
            return r.json().get("response", "")
        except Exception:
            return ""

    def _ask_model_json(self, prompt: str) -> Dict:
        text = self._ask_model(prompt)
        try:
            start = text.find("{")
            end = text.rfind("}") + 1
            if start != -1 and end > start:
                return json.loads(text[start:end])
        except Exception:
            pass
        return {}

    # ── Detection Rules ────────────────────────────────────────
    def _build_rules(self):
        self.rules = [
            # SQL Injection
            (r"('|\")(\s*OR\s*|\s*AND\s*)(\s*['\"]?\s*\d+\s*=\s*\d+)", "SQL Injection", "BLOCK", "CRITICAL", 0.97),
            (r"(SELECT\s+\*\s+FROM|INSERT\s+INTO|DROP\s+TABLE|UPDATE\s+\w+\s+SET|DELETE\s+FROM)", "SQL Injection", "BLOCK", "CRITICAL", 0.96),
            (r"(UNION\s+(ALL\s+)?SELECT|ORDER\s+BY\s+\d+--|GROUP\s+BY\s+\d+--)", "SQL Injection", "BLOCK", "CRITICAL", 0.96),
            (r"(EXEC\s+XP_CMDSHELL|WAITFOR\s+DELAY|BENCHMARK\s*\(|SLEEP\s*\(|PG_SLEEP)", "SQL Injection", "BLOCK", "CRITICAL", 0.97),
            (r"(--|#|/\*.*\*/)\s*$", "SQL Injection", "BLOCK", "HIGH", 0.88),

            # XSS
            (r"<script[^>]*>", "XSS", "BLOCK", "CRITICAL", 0.96),
            (r"(javascript:|vbscript:|data:\s*text/html)", "XSS", "BLOCK", "CRITICAL", 0.95),
            (r"(onload|onerror|onmouseover|onfocus|onclick)\s*=", "XSS", "BLOCK", "HIGH", 0.92),
            (r"(alert|prompt|confirm|eval)\s*\(", "XSS", "ISOLATE", "HIGH", 0.90),
            (r"(document\.(cookie|location|write)|window\.(location|open))", "XSS", "BLOCK", "HIGH", 0.91),

            # Command Injection
            (r";\s*(cat|ls|rm|wget|curl|bash|sh|nc|netcat|python|perl|ruby)\s+", "Command Injection", "BLOCK", "CRITICAL", 0.96),
            (r"\|\s*(cat|ls|rm|wget|curl|bash|sh|nc|netcat)\s+", "Command Injection", "BLOCK", "CRITICAL", 0.95),
            (r"`[^`]*`", "Command Injection", "BLOCK", "HIGH", 0.90),
            (r"\$\([^)]*\)", "Command Injection", "BLOCK", "HIGH", 0.89),
            (r"(powershell\s+.*-enc|certutil\s+.*-decode)", "Command Injection", "BLOCK", "CRITICAL", 0.97),

            # Path Traversal
            (r"(\.\./|\.\.\\){2,}", "Path Traversal", "BLOCK", "HIGH", 0.93),
            (r"/etc/(passwd|shadow|hosts|crontab)", "Path Traversal", "BLOCK", "CRITICAL", 0.96),
            (r"(C:\\Windows\\system32|C:\\boot\.ini)", "Path Traversal", "BLOCK", "CRITICAL", 0.95),

            # Code Injection
            (r"(<\?php|<\?=|eval\s*\(|base64_decode\s*\(|gzinflate)", "Code Injection", "BLOCK", "CRITICAL", 0.96),
            (r"(php://input|php://filter|expect://|phar://)", "Code Injection", "BLOCK", "CRITICAL", 0.97),

            # SSRF
            (r"(169\.254\.\d+\.\d+|metadata\.google\.internal)", "SSRF", "BLOCK", "CRITICAL", 0.95),
            (r"(http://localhost|http://127\.0\.0\.1|http://0\.0\.0\.0)", "SSRF", "BLOCK", "HIGH", 0.88),
            (r"(http://10\.\d+|http://172\.(1[6-9]|2\d|3[01])\.|http://192\.168\.)", "SSRF", "BLOCK", "HIGH", 0.85),

            # XXE
            (r"(<!DOCTYPE[^>]*\[|<!ENTITY\s+\w+\s+SYSTEM)", "XXE", "BLOCK", "CRITICAL", 0.95),

            # Template Injection
            (r"(\{\{.*\}\}|\$\{.*\}|%\{.*\}|#\{.*\})", "Template Injection", "ISOLATE", "HIGH", 0.87),

            # LDAP Injection
            (r"(\*\)\(\||\)\(\&|\)\(!\|)", "LDAP Injection", "BLOCK", "HIGH", 0.88),

            # NoSQL Injection
            (r"(\$gt|\$lt|\$ne|\$regex|\$where|\$exists)", "NoSQL Injection", "BLOCK", "HIGH", 0.90),

            # File Upload attacks
            (r"\.(php|jsp|asp|aspx|exe|bat|cmd|sh|cgi|pl)\s*$", "Malicious Upload", "BLOCK", "HIGH", 0.85),

            # Log4Shell
            (r"\$\{jndi:(ldap|rmi|dns|iiop)://", "Log4Shell", "BLOCK", "CRITICAL", 0.99),
        ]

    # ── Evasion Detection ──────────────────────────────────────
    def detect_evasion(self, payload: str) -> Dict:
        evasion_techniques = []
        score = 0.0

        checks = [
            (r"(?:%[0-9a-fA-F]{2}){3,}", "URL Encoding", 0.3),
            (r"[A-Za-z0-9+/]{20,}={0,2}", "Base64 Encoding", 0.4),
            (r"(?:\\x[0-9a-fA-F]{2}){3,}", "Hex Encoding", 0.3),
            (r"(?:\\u[0-9a-fA-F]{4}){2,}", "Unicode Escape", 0.35),
            (r"(?:&#\d{2,3};){3,}", "HTML Entity Encoding", 0.3),
            (r"[sS][eE][lL][eE][cC][tT]", "Case Randomization", 0.25),
            (r"(/\*.*?\*/|<!--.*?-->)", "Comment Insertion", 0.3),
            (r"(%25|%2525)", "Double URL Encoding", 0.5),
        ]

        for pattern, technique, weight in checks:
            if re.search(pattern, payload, re.IGNORECASE | re.DOTALL):
                evasion_techniques.append(technique)
                score += weight

        return {
            "evasion_detected": len(evasion_techniques) > 0,
            "techniques": evasion_techniques,
            "evasion_score": round(min(score, 1.0), 3)
        }

    # ── Payload Extraction ─────────────────────────────────────
    def extract_payload(self, raw_data: str) -> Tuple[str, Dict]:
        context = {"method": "UNKNOWN", "path": "/", "headers": {}, "body": ""}
        if not raw_data:
            return "", context

        if "HTTP/" in raw_data:
            lines = raw_data.split("\r\n") if "\r\n" in raw_data else raw_data.split("\n")
            first = lines[0] if lines else ""
            parts = first.split(" ")
            if len(parts) >= 2:
                context["method"] = parts[0]
                context["path"] = parts[1]

            header_done = False
            for line in lines[1:]:
                if not line.strip():
                    header_done = True
                    continue
                if not header_done and ":" in line:
                    k, v = line.split(":", 1)
                    context["headers"][k.strip().lower()] = v.strip()
                elif header_done:
                    context["body"] += line

            # Extract from URL params
            if "?" in context["path"]:
                query = context["path"].split("?", 1)[1]
                return query, context
            if context["body"].strip():
                return context["body"].strip(), context

        return raw_data[:500], context

    # ── Rule-based Detection ───────────────────────────────────
    def detect_by_rules(self, payload: str) -> Optional[Dict]:
        if not payload or len(payload.strip()) < 2:
            return None
        payload_lower = payload.lower()
        for pattern, attack_type, action, classification, confidence in self.rules:
            try:
                match = re.search(pattern, payload_lower, re.IGNORECASE)
                if match:
                    return {
                        "attack_type": attack_type,
                        "action": action,
                        "classification": classification,
                        "confidence": confidence,
                        "signature": match.group(0)[:80],
                        "method": "rule-based"
                    }
            except Exception:
                continue
        return None

    # ── AI-Enhanced Analysis ───────────────────────────────────
    def analyze_with_ai(self, payload: str, context: Dict) -> Dict:
        prompt = (
            "You are ZeroCyber, a cybersecurity AI. Analyze this network payload.\n"
            "Respond ONLY with valid JSON, no other text.\n\n"
            "JSON format:\n"
            '{"attack_type": "...", "action": "BLOCK|ISOLATE|MONITOR|LOG",'
            ' "classification": "CRITICAL|HIGH|MEDIUM|LOW",'
            ' "confidence": 0.0-1.0,'
            ' "insight": "detailed analysis of the threat",'
            ' "cve_related": "CVE-XXXX-XXXX or none",'
            ' "kill_chain_phase": "reconnaissance|weaponization|delivery|exploitation|installation|c2|exfiltration"}\n\n'
            f"HTTP Method: {context.get('method', 'UNKNOWN')}\n"
            f"Path: {context.get('path', '/')}\n"
            f"Payload: {payload[:400]}"
        )
        return self._ask_model_json(prompt)

    # ── Main Analysis Pipeline ─────────────────────────────────
    def analyze(self, raw_data: str, source_ip: str = "unknown") -> Dict:
        start = datetime.now()

        # 1. Extract payload
        clean_payload, context = self.extract_payload(raw_data)
        payload_hash = hashlib.sha256(raw_data.encode(errors="replace")).hexdigest()

        # 2. Evasion detection
        evasion = self.detect_evasion(clean_payload)

        # 3. Fast rule-based detection
        rule_result = self.detect_by_rules(clean_payload)

        # 4. AI enhancement
        detection_method = "rule-based"
        ai_insight = ""
        cve_related = ""
        kill_chain = ""

        if self.ollama_available:
            ai_result = self.analyze_with_ai(clean_payload, context)
            if ai_result:
                detection_method = "ZeroCyber-SLM + Rules" if rule_result else "ZeroCyber-SLM"
                ai_insight = ai_result.get("insight", "")
                cve_related = ai_result.get("cve_related", "")
                kill_chain = ai_result.get("kill_chain_phase", "")

                if not rule_result:
                    rule_result = {
                        "attack_type": ai_result.get("attack_type", "Unknown"),
                        "action": ai_result.get("action", "LOG"),
                        "classification": ai_result.get("classification", "LOW"),
                        "confidence": float(ai_result.get("confidence", 0.5)),
                        "signature": clean_payload[:40],
                        "method": "ZeroCyber-SLM"
                    }
                else:
                    # Blend confidence
                    model_conf = float(ai_result.get("confidence", rule_result["confidence"]))
                    rule_result["confidence"] = round((rule_result["confidence"] + model_conf) / 2, 3)

        # 5. Defaults
        if not rule_result:
            rule_result = {
                "attack_type": "Unknown",
                "action": "LOG",
                "classification": "LOW",
                "confidence": 0.3,
                "signature": clean_payload[:30],
                "method": "none"
            }

        # 6. Boost confidence if evasion detected
        if evasion["evasion_detected"] and rule_result["classification"] != "CRITICAL":
            rule_result["confidence"] = min(rule_result["confidence"] + 0.1, 1.0)
            if rule_result["classification"] == "LOW":
                rule_result["classification"] = "MEDIUM"
            elif rule_result["classification"] == "MEDIUM":
                rule_result["classification"] = "HIGH"

        process_time = (datetime.now() - start).total_seconds() * 1000

        return {
            "timestamp": datetime.now().isoformat(),
            "source_ip": source_ip,
            "attack_type": rule_result["attack_type"],
            "classification": rule_result["classification"],
            "confidence": rule_result["confidence"],
            "action": rule_result["action"],
            "signature": rule_result["signature"],
            "detection_method": detection_method,
            "ai_insight": ai_insight,
            "cve_related": cve_related,
            "kill_chain_phase": kill_chain,
            "evasion": evasion,
            "context": {
                "method": context.get("method"),
                "path": context.get("path"),
            },
            "payload_preview": clean_payload[:200],
            "payload_hash": payload_hash,
            "processing_time_ms": round(process_time, 2)
        }

    # ── Chat Interface (for forensics & red team) ──────────────
    def chat(self, message: str, system_context: str = "") -> str:
        if not self.ollama_available:
            return "ZeroCyber-SLM model is not available. Please start Ollama."
        base = "You are ZeroCyber, an expert cybersecurity AI specialized in threat analysis, digital forensics, incident response, and red/blue team operations."
        if system_context:
            base += f"\n\nContext: {system_context}"
        prompt = f"{base}\n\nUser: {message}\n\nZeroCyber:"
        return self._ask_model(prompt, timeout=180)
