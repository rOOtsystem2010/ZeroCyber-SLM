# ===== threat_hunter.py =====
"""
ZeroCyber Autonomous Threat Hunter
Proactively hunts for threats by analyzing system logs, processes, and network connections.
Works 100% offline - unique capability no cloud product offers.
"""

import os
import re
import json
import subprocess
import platform
import hashlib
import uuid
from datetime import datetime
from typing import Dict, List, Optional
from zerocyber_engine import ZeroCyberEngine


class ThreatHunter:
    """Autonomous system threat hunter - works offline on the host machine."""

    def __init__(self, engine: ZeroCyberEngine):
        self.engine = engine
        self.os_type = platform.system().lower()

    def run_full_hunt(self) -> Dict:
        """Execute a complete threat hunting session."""
        session_id = f"HUNT-{uuid.uuid4().hex[:8].upper()}"
        started = datetime.now()
        findings = []

        # Run all hunters
        hunters = [
            ("Suspicious Processes", self.hunt_suspicious_processes),
            ("Network Connections", self.hunt_network_anomalies),
            ("Startup Persistence", self.hunt_persistence_mechanisms),
            ("Suspicious Files", self.hunt_suspicious_files),
            ("Log Anomalies", self.hunt_log_anomalies),
        ]

        for name, hunter_fn in hunters:
            try:
                result = hunter_fn()
                if result:
                    findings.extend(result)
            except Exception as e:
                findings.append({
                    "category": name,
                    "severity": "INFO",
                    "finding": f"Hunter error: {str(e)[:100]}",
                    "timestamp": datetime.now().isoformat()
                })

        # AI enrichment if available
        if self.engine.ollama_available and findings:
            findings = self._enrich_with_ai(findings)

        return {
            "session_id": session_id,
            "started_at": started.isoformat(),
            "completed_at": datetime.now().isoformat(),
            "os": self.os_type,
            "findings_count": len(findings),
            "critical_count": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
            "high_count": sum(1 for f in findings if f.get("severity") == "HIGH"),
            "findings": findings
        }

    # ── Process Hunter ─────────────────────────────────────────
    def hunt_suspicious_processes(self) -> List[Dict]:
        findings = []
        processes = self._get_processes()

        # Known suspicious process names
        suspicious_names = [
            "mimikatz", "lazagne", "bloodhound", "sharphound",
            "rubeus", "certify", "seatbelt", "winpeas", "linpeas",
            "chisel", "ligolo", "sliver", "cobalt", "beacon",
            "meterpreter", "empire", "covenant", "poshc2",
            "nc.exe", "ncat", "socat", "cryptominer", "xmrig",
            "powershell -enc", "cmd /c whoami", "certutil -decode",
        ]

        # Known legitimate process hashes (whitelist concept)
        for proc in processes:
            name_lower = proc.get("name", "").lower()
            cmdline = proc.get("cmdline", "").lower()

            # Check suspicious names
            for susp in suspicious_names:
                if susp in name_lower or susp in cmdline:
                    findings.append({
                        "category": "Suspicious Process",
                        "severity": "CRITICAL",
                        "finding": f"Potentially malicious process detected: {proc['name']} (PID: {proc.get('pid', '?')})",
                        "details": {
                            "process_name": proc.get("name"),
                            "pid": proc.get("pid"),
                            "command_line": proc.get("cmdline", "")[:200],
                            "matched_pattern": susp
                        },
                        "mitre": "T1059 - Command and Scripting Interpreter",
                        "timestamp": datetime.now().isoformat()
                    })

            # Check for encoded PowerShell
            if "powershell" in name_lower and ("-enc" in cmdline or "-encodedcommand" in cmdline or "bypass" in cmdline):
                findings.append({
                    "category": "Suspicious Process",
                    "severity": "HIGH",
                    "finding": f"Encoded/bypass PowerShell execution: PID {proc.get('pid', '?')}",
                    "details": {"command_line": proc.get("cmdline", "")[:300]},
                    "mitre": "T1059.001 - PowerShell",
                    "timestamp": datetime.now().isoformat()
                })

            # Check for reverse shells
            if any(x in cmdline for x in ["bash -i", "/dev/tcp", "mkfifo", "nc -e", "ncat -e"]):
                findings.append({
                    "category": "Reverse Shell",
                    "severity": "CRITICAL",
                    "finding": f"Possible reverse shell: PID {proc.get('pid', '?')}",
                    "details": {"command_line": proc.get("cmdline", "")[:300]},
                    "mitre": "T1059.004 - Unix Shell",
                    "timestamp": datetime.now().isoformat()
                })

        return findings

    # ── Network Hunter ─────────────────────────────────────────
    def hunt_network_anomalies(self) -> List[Dict]:
        findings = []
        connections = self._get_network_connections()

        # Suspicious ports (common C2, malware, backdoors)
        suspicious_ports = {
            4444: "Metasploit default",
            5555: "Android ADB",
            6666: "IRC backdoor",
            6667: "IRC C2",
            8888: "Common backdoor",
            9999: "Common backdoor",
            1234: "Common backdoor",
            31337: "Elite backdoor",
            12345: "NetBus trojan",
            65535: "Suspicious high port",
            4443: "Cobalt Strike",
            8443: "Suspicious HTTPS alt",
            3389: "RDP (verify if expected)",
        }

        # Known bad IP ranges
        for conn in connections:
            remote_port = conn.get("remote_port", 0)
            remote_ip = conn.get("remote_ip", "")
            state = conn.get("state", "")

            # Check suspicious ports
            if remote_port in suspicious_ports and state == "ESTABLISHED":
                findings.append({
                    "category": "Suspicious Connection",
                    "severity": "HIGH",
                    "finding": f"Connection to suspicious port {remote_port} ({suspicious_ports[remote_port]})",
                    "details": {
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "state": state,
                        "pid": conn.get("pid", "?"),
                        "reason": suspicious_ports[remote_port]
                    },
                    "mitre": "T1571 - Non-Standard Port",
                    "timestamp": datetime.now().isoformat()
                })

            # Check for connections to private IPs from server (potential SSRF)
            if remote_ip and state == "ESTABLISHED":
                if remote_ip.startswith(("169.254.", "0.0.0.")):
                    findings.append({
                        "category": "Suspicious Connection",
                        "severity": "CRITICAL",
                        "finding": f"Connection to metadata/link-local address: {remote_ip}",
                        "details": conn,
                        "mitre": "T1552 - Unsecured Credentials",
                        "timestamp": datetime.now().isoformat()
                    })

        return findings

    # ── Persistence Hunter ─────────────────────────────────────
    def hunt_persistence_mechanisms(self) -> List[Dict]:
        findings = []

        if self.os_type == "windows":
            findings.extend(self._hunt_windows_persistence())
        else:
            findings.extend(self._hunt_linux_persistence())

        return findings

    def _hunt_windows_persistence(self) -> List[Dict]:
        findings = []
        # Check startup registry keys
        reg_keys = [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        ]
        for key in reg_keys:
            try:
                result = subprocess.run(
                    ["reg", "query", key],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    lines = result.stdout.strip().split("\n")
                    for line in lines:
                        line = line.strip()
                        if not line or line.startswith("HK"):
                            continue
                        # Check for suspicious entries
                        suspicious_indicators = [
                            "powershell", "cmd /c", "wscript", "cscript",
                            "mshta", "regsvr32", "rundll32", "certutil",
                            "bitsadmin", ".vbs", ".js", ".hta",
                            "temp", "appdata\\local\\temp"
                        ]
                        line_lower = line.lower()
                        for indicator in suspicious_indicators:
                            if indicator in line_lower:
                                findings.append({
                                    "category": "Persistence",
                                    "severity": "HIGH",
                                    "finding": f"Suspicious startup entry in {key}",
                                    "details": {
                                        "registry_key": key,
                                        "entry": line[:200],
                                        "matched": indicator
                                    },
                                    "mitre": "T1547.001 - Registry Run Keys",
                                    "timestamp": datetime.now().isoformat()
                                })
                                break
            except Exception:
                continue

        # Check scheduled tasks
        try:
            result = subprocess.run(
                ["schtasks", "/query", "/fo", "CSV", "/nh"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    line_lower = line.lower()
                    if any(s in line_lower for s in ["powershell", "cmd", "wscript", "temp"]):
                        findings.append({
                            "category": "Persistence",
                            "severity": "MEDIUM",
                            "finding": "Suspicious scheduled task detected",
                            "details": {"task": line.strip()[:200]},
                            "mitre": "T1053.005 - Scheduled Task",
                            "timestamp": datetime.now().isoformat()
                        })
        except Exception:
            pass

        return findings

    def _hunt_linux_persistence(self) -> List[Dict]:
        findings = []
        # Check crontabs
        cron_paths = ["/etc/crontab", "/var/spool/cron/", "/etc/cron.d/"]
        for path in cron_paths:
            if os.path.exists(path):
                if os.path.isfile(path):
                    try:
                        with open(path, "r", errors="ignore") as f:
                            content = f.read()
                        suspicious = ["wget", "curl", "bash -i", "/dev/tcp", "nc ", "python -c"]
                        for s in suspicious:
                            if s in content.lower():
                                findings.append({
                                    "category": "Persistence",
                                    "severity": "HIGH",
                                    "finding": f"Suspicious cron entry in {path}",
                                    "details": {"matched": s, "file": path},
                                    "mitre": "T1053.003 - Cron",
                                    "timestamp": datetime.now().isoformat()
                                })
                    except Exception:
                        pass

        # Check SSH authorized_keys
        ssh_paths = [
            os.path.expanduser("~/.ssh/authorized_keys"),
            "/root/.ssh/authorized_keys"
        ]
        for path in ssh_paths:
            if os.path.exists(path):
                try:
                    with open(path, "r", errors="ignore") as f:
                        keys = f.readlines()
                    if len(keys) > 5:
                        findings.append({
                            "category": "Persistence",
                            "severity": "MEDIUM",
                            "finding": f"Multiple SSH keys ({len(keys)}) in {path}",
                            "details": {"key_count": len(keys), "file": path},
                            "mitre": "T1098.004 - SSH Authorized Keys",
                            "timestamp": datetime.now().isoformat()
                        })
                except Exception:
                    pass

        return findings

    # ── File Hunter ────────────────────────────────────────────
    def hunt_suspicious_files(self) -> List[Dict]:
        findings = []
        # Check common webshell / malware directories
        check_dirs = []
        if self.os_type == "windows":
            check_dirs = [
                os.environ.get("TEMP", "C:\\Temp"),
                os.path.join(os.environ.get("USERPROFILE", ""), "Downloads"),
            ]
        else:
            check_dirs = ["/tmp", "/var/tmp", "/dev/shm"]

        suspicious_extensions = [
            ".php", ".jsp", ".asp", ".aspx", ".exe", ".bat", ".cmd",
            ".ps1", ".vbs", ".hta", ".scr", ".pif", ".com"
        ]

        for dir_path in check_dirs:
            if not os.path.exists(dir_path):
                continue
            try:
                for item in os.listdir(dir_path):
                    item_lower = item.lower()
                    full_path = os.path.join(dir_path, item)
                    if not os.path.isfile(full_path):
                        continue

                    # Check suspicious extensions in temp dirs
                    for ext in suspicious_extensions:
                        if item_lower.endswith(ext):
                            findings.append({
                                "category": "Suspicious File",
                                "severity": "MEDIUM",
                                "finding": f"Suspicious file in temp directory: {item}",
                                "details": {
                                    "path": full_path,
                                    "extension": ext,
                                    "size_bytes": os.path.getsize(full_path)
                                },
                                "mitre": "T1105 - Ingress Tool Transfer",
                                "timestamp": datetime.now().isoformat()
                            })
                            break
            except PermissionError:
                continue

        return findings

    # ── Log Hunter ─────────────────────────────────────────────
    def hunt_log_anomalies(self) -> List[Dict]:
        findings = []

        if self.os_type == "windows":
            findings.extend(self._hunt_windows_logs())

        return findings

    def _hunt_windows_logs(self) -> List[Dict]:
        findings = []
        # Check for failed login attempts (Event ID 4625)
        try:
            result = subprocess.run(
                ["wevtutil", "qe", "Security", "/q:*[System[EventID=4625]]",
                 "/c:20", "/f:text", "/rd:true"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                failed_count = result.stdout.count("Event ID: 4625")
                if failed_count > 0:
                    findings.append({
                        "category": "Authentication",
                        "severity": "MEDIUM" if failed_count < 10 else "HIGH",
                        "finding": f"{failed_count} failed login attempts detected in recent logs",
                        "details": {"event_id": 4625, "count": failed_count},
                        "mitre": "T1110 - Brute Force",
                        "timestamp": datetime.now().isoformat()
                    })
        except Exception:
            pass

        # Check for service installations (Event ID 7045)
        try:
            result = subprocess.run(
                ["wevtutil", "qe", "System", "/q:*[System[EventID=7045]]",
                 "/c:10", "/f:text", "/rd:true"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                suspicious_services = ["powershell", "cmd", "temp", "appdata"]
                for s in suspicious_services:
                    if s in result.stdout.lower():
                        findings.append({
                            "category": "Persistence",
                            "severity": "HIGH",
                            "finding": "Suspicious service installation detected",
                            "details": {"event_id": 7045, "matched": s},
                            "mitre": "T1543.003 - Windows Service",
                            "timestamp": datetime.now().isoformat()
                        })
        except Exception:
            pass

        return findings

    # ── AI Enrichment ──────────────────────────────────────────
    def _enrich_with_ai(self, findings: List[Dict]) -> List[Dict]:
        """Use ZeroCyber-SLM to add context and recommendations to findings."""
        summary = "\n".join([
            f"- [{f['severity']}] {f['finding']}"
            for f in findings[:15]
        ])

        prompt = (
            "You are ZeroCyber, a threat hunting AI. Analyze these findings from a system scan.\n"
            "Respond with JSON only.\n"
            "JSON format: {\"assessment\": \"overall risk assessment\", "
            "\"correlation\": \"how findings relate to each other\", "
            "\"priority_actions\": [\"action1\", \"action2\", \"action3\"]}\n\n"
            f"Findings:\n{summary}"
        )

        ai_result = self.engine._ask_model_json(prompt)
        if ai_result:
            for f in findings:
                f["ai_assessment"] = ai_result.get("assessment", "")
                f["ai_correlation"] = ai_result.get("correlation", "")
            # Add AI summary as first finding
            findings.insert(0, {
                "category": "AI Assessment",
                "severity": "INFO",
                "finding": ai_result.get("assessment", "Analysis complete"),
                "details": {
                    "correlation": ai_result.get("correlation", ""),
                    "priority_actions": ai_result.get("priority_actions", [])
                },
                "timestamp": datetime.now().isoformat()
            })

        return findings

    # ── OS Helpers ─────────────────────────────────────────────
    def _get_processes(self) -> List[Dict]:
        processes = []
        try:
            if self.os_type == "windows":
                result = subprocess.run(
                    ["wmic", "process", "get", "Name,ProcessId,CommandLine", "/format:csv"],
                    capture_output=True, text=True, timeout=15
                )
                if result.returncode == 0:
                    for line in result.stdout.strip().split("\n")[1:]:
                        parts = line.strip().split(",")
                        if len(parts) >= 4:
                            processes.append({
                                "name": parts[2].strip(),
                                "pid": parts[3].strip(),
                                "cmdline": parts[1].strip()
                            })
            else:
                result = subprocess.run(
                    ["ps", "aux", "--no-headers"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    for line in result.stdout.strip().split("\n"):
                        parts = line.split(None, 10)
                        if len(parts) >= 11:
                            processes.append({
                                "name": parts[10].split("/")[-1].split()[0],
                                "pid": parts[1],
                                "cmdline": parts[10]
                            })
        except Exception:
            pass
        return processes

    def _get_network_connections(self) -> List[Dict]:
        connections = []
        try:
            if self.os_type == "windows":
                result = subprocess.run(
                    ["netstat", "-ano"],
                    capture_output=True, text=True, timeout=10
                )
            else:
                result = subprocess.run(
                    ["ss", "-tunap"],
                    capture_output=True, text=True, timeout=10
                )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    parts = line.split()
                    if len(parts) >= 4 and ("ESTABLISHED" in line or "LISTEN" in line):
                        try:
                            remote = parts[2] if self.os_type != "windows" else parts[2]
                            if ":" in remote:
                                ip, port = remote.rsplit(":", 1)
                                connections.append({
                                    "remote_ip": ip.strip("[]"),
                                    "remote_port": int(port) if port.isdigit() else 0,
                                    "state": "ESTABLISHED" if "ESTABLISHED" in line else "LISTEN",
                                    "pid": parts[-1] if parts[-1].isdigit() else "?"
                                })
                        except (ValueError, IndexError):
                            continue
        except Exception:
            pass
        return connections
