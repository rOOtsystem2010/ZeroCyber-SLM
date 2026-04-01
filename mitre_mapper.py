# ===== mitre_mapper.py =====
"""
ZeroCyber MITRE ATT&CK Mapper
Maps detected attacks to MITRE ATT&CK Framework tactics, techniques, and kill chain phases.
"""

from typing import Dict, List, Optional


# Complete MITRE ATT&CK mapping database
MITRE_DATABASE = {
    "SQL Injection": {
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "sub_techniques": ["T1190.001"],
        "kill_chain": ["delivery", "exploitation"],
        "severity_base": 9.8,
        "description": "Adversary exploits SQL injection in web application to gain unauthorized database access.",
        "mitigations": [
            {"id": "M1030", "name": "Network Segmentation"},
            {"id": "M1050", "name": "Exploit Protection"},
            {"id": "M1016", "name": "Vulnerability Scanning"}
        ],
        "data_sources": ["Application Log", "Network Traffic Content", "Web Application Firewall Logs"],
        "platforms": ["Linux", "Windows", "macOS", "Cloud"],
        "detection_tips": [
            "Monitor web server logs for SQL error messages",
            "Inspect HTTP parameters for SQL metacharacters",
            "Watch for unusual database query patterns"
        ]
    },
    "XSS": {
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "technique_id": "T1189",
        "technique_name": "Drive-by Compromise",
        "sub_techniques": ["T1189.001"],
        "kill_chain": ["delivery", "exploitation"],
        "severity_base": 7.5,
        "description": "Adversary injects malicious scripts into web pages viewed by other users.",
        "mitigations": [
            {"id": "M1050", "name": "Exploit Protection"},
            {"id": "M1048", "name": "Application Isolation and Sandboxing"}
        ],
        "data_sources": ["Application Log", "Network Traffic Content"],
        "platforms": ["Linux", "Windows", "macOS"],
        "detection_tips": [
            "Monitor for script tags in user input",
            "Check Content-Security-Policy headers",
            "Inspect DOM modifications"
        ]
    },
    "Command Injection": {
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "sub_techniques": ["T1059.001", "T1059.003", "T1059.004"],
        "kill_chain": ["exploitation", "installation"],
        "severity_base": 9.8,
        "description": "Adversary executes OS commands through vulnerable application input.",
        "mitigations": [
            {"id": "M1038", "name": "Execution Prevention"},
            {"id": "M1040", "name": "Behavior Prevention on Endpoint"},
            {"id": "M1026", "name": "Privileged Account Management"}
        ],
        "data_sources": ["Command Execution", "Process Creation", "Script Execution"],
        "platforms": ["Linux", "Windows", "macOS"],
        "detection_tips": [
            "Monitor process creation from web server processes",
            "Watch for shell spawning from application context",
            "Check for unusual command-line arguments"
        ]
    },
    "Path Traversal": {
        "tactic_id": "TA0009",
        "tactic_name": "Collection",
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "sub_techniques": [],
        "kill_chain": ["exploitation"],
        "severity_base": 7.5,
        "description": "Adversary manipulates file paths to access restricted directories and files.",
        "mitigations": [
            {"id": "M1017", "name": "User Training"},
            {"id": "M1022", "name": "Restrict File and Directory Permissions"}
        ],
        "data_sources": ["File Access", "Application Log"],
        "platforms": ["Linux", "Windows", "macOS"],
        "detection_tips": [
            "Monitor for ../ sequences in HTTP requests",
            "Watch for access to sensitive system files",
            "Check web server access logs for path manipulation"
        ]
    },
    "Code Injection": {
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "sub_techniques": ["T1055.001", "T1055.012"],
        "kill_chain": ["exploitation", "installation"],
        "severity_base": 9.0,
        "description": "Adversary injects malicious code into running application process.",
        "mitigations": [
            {"id": "M1040", "name": "Behavior Prevention on Endpoint"},
            {"id": "M1026", "name": "Privileged Account Management"}
        ],
        "data_sources": ["Process Modification", "Module Load", "OS API Execution"],
        "platforms": ["Linux", "Windows", "macOS"],
        "detection_tips": [
            "Monitor for eval/exec function calls in web apps",
            "Watch for dynamic code compilation",
            "Check for uploaded web shells"
        ]
    },
    "SSRF": {
        "tactic_id": "TA0043",
        "tactic_name": "Reconnaissance",
        "technique_id": "T1592",
        "technique_name": "Gather Victim Host Information",
        "sub_techniques": ["T1592.004"],
        "kill_chain": ["reconnaissance", "delivery"],
        "severity_base": 8.6,
        "description": "Adversary abuses server to make requests to internal resources, accessing cloud metadata or internal services.",
        "mitigations": [
            {"id": "M1030", "name": "Network Segmentation"},
            {"id": "M1031", "name": "Network Intrusion Prevention"}
        ],
        "data_sources": ["Network Traffic Flow", "Application Log", "Cloud Service"],
        "platforms": ["Linux", "Windows", "Cloud"],
        "detection_tips": [
            "Monitor outbound requests from web servers",
            "Block access to cloud metadata endpoints",
            "Watch for requests to internal IP ranges"
        ]
    },
    "XXE": {
        "tactic_id": "TA0009",
        "tactic_name": "Collection",
        "technique_id": "T1213",
        "technique_name": "Data from Information Repositories",
        "sub_techniques": [],
        "kill_chain": ["exploitation"],
        "severity_base": 9.0,
        "description": "Adversary exploits XML parser to read local files or make server-side requests.",
        "mitigations": [
            {"id": "M1054", "name": "Software Configuration"},
            {"id": "M1050", "name": "Exploit Protection"}
        ],
        "data_sources": ["Application Log", "Network Traffic Content"],
        "platforms": ["Linux", "Windows", "macOS"],
        "detection_tips": [
            "Monitor for DOCTYPE and ENTITY declarations in XML input",
            "Disable external entity processing in XML parsers",
            "Watch for file:// protocol in XML content"
        ]
    },
    "Template Injection": {
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "sub_techniques": ["T1059.007"],
        "kill_chain": ["exploitation"],
        "severity_base": 8.8,
        "description": "Adversary injects template syntax to execute code on the server-side template engine.",
        "mitigations": [
            {"id": "M1038", "name": "Execution Prevention"},
            {"id": "M1050", "name": "Exploit Protection"}
        ],
        "data_sources": ["Application Log", "Process Creation"],
        "platforms": ["Linux", "Windows", "macOS"],
        "detection_tips": [
            "Monitor for template syntax ({{ }}, ${ }) in user input",
            "Check template rendering errors in application logs",
            "Use template sandboxing"
        ]
    },
    "LDAP Injection": {
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "technique_id": "T1556",
        "technique_name": "Modify Authentication Process",
        "sub_techniques": [],
        "kill_chain": ["exploitation"],
        "severity_base": 8.0,
        "description": "Adversary manipulates LDAP queries to bypass authentication or extract directory information.",
        "mitigations": [
            {"id": "M1027", "name": "Password Policies"},
            {"id": "M1032", "name": "Multi-factor Authentication"}
        ],
        "data_sources": ["Application Log", "Logon Session"],
        "platforms": ["Linux", "Windows"],
        "detection_tips": [
            "Monitor LDAP query patterns for injection markers",
            "Watch for unusual directory enumeration",
            "Check for LDAP error spikes"
        ]
    },
    "NoSQL Injection": {
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "sub_techniques": [],
        "kill_chain": ["delivery", "exploitation"],
        "severity_base": 8.5,
        "description": "Adversary injects NoSQL operators to bypass authentication or extract data from document databases.",
        "mitigations": [
            {"id": "M1050", "name": "Exploit Protection"},
            {"id": "M1016", "name": "Vulnerability Scanning"}
        ],
        "data_sources": ["Application Log", "Network Traffic Content"],
        "platforms": ["Linux", "Windows", "macOS", "Cloud"],
        "detection_tips": [
            "Monitor for $gt, $ne, $regex operators in requests",
            "Validate JSON input structure",
            "Watch for unusual MongoDB query patterns"
        ]
    },
    "Malicious Upload": {
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "sub_techniques": [],
        "kill_chain": ["delivery", "installation"],
        "severity_base": 8.0,
        "description": "Adversary uploads malicious files (web shells, executables) to gain persistent access.",
        "mitigations": [
            {"id": "M1031", "name": "Network Intrusion Prevention"},
            {"id": "M1034", "name": "Limit Access to Resource Over Network"}
        ],
        "data_sources": ["File Creation", "Network Traffic Content"],
        "platforms": ["Linux", "Windows", "macOS"],
        "detection_tips": [
            "Validate file types beyond extension",
            "Monitor web upload directories",
            "Scan uploaded files for malicious content"
        ]
    },
    "Log4Shell": {
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution",
        "sub_techniques": [],
        "kill_chain": ["delivery", "exploitation", "installation", "c2"],
        "severity_base": 10.0,
        "description": "CVE-2021-44228: Remote code execution via JNDI injection in Apache Log4j2.",
        "mitigations": [
            {"id": "M1051", "name": "Update Software"},
            {"id": "M1050", "name": "Exploit Protection"}
        ],
        "data_sources": ["Application Log", "Network Traffic Content", "Process Creation"],
        "platforms": ["Linux", "Windows", "macOS"],
        "detection_tips": [
            "Search for ${jndi: patterns in all log sources",
            "Monitor for outbound LDAP/RMI connections",
            "Check Java process spawning suspicious child processes"
        ]
    },
    "Brute Force": {
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "sub_techniques": ["T1110.001", "T1110.002", "T1110.003", "T1110.004"],
        "kill_chain": ["exploitation"],
        "severity_base": 5.0,
        "description": "Adversary systematically guesses passwords to gain account access.",
        "mitigations": [
            {"id": "M1032", "name": "Multi-factor Authentication"},
            {"id": "M1036", "name": "Account Use Policies"},
            {"id": "M1027", "name": "Password Policies"}
        ],
        "data_sources": ["User Account Authentication", "Application Log"],
        "platforms": ["Linux", "Windows", "macOS", "Cloud"],
        "detection_tips": [
            "Monitor for multiple failed login attempts",
            "Track authentication source IP patterns",
            "Implement account lockout policies"
        ]
    },
    "Unknown": {
        "tactic_id": "TA0043",
        "tactic_name": "Reconnaissance",
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
        "sub_techniques": ["T1595.001", "T1595.002"],
        "kill_chain": ["reconnaissance"],
        "severity_base": 3.0,
        "description": "Unclassified suspicious activity that may indicate reconnaissance or probing.",
        "mitigations": [
            {"id": "M1056", "name": "Pre-compromise"},
            {"id": "M1031", "name": "Network Intrusion Prevention"}
        ],
        "data_sources": ["Network Traffic Flow", "Network Traffic Content"],
        "platforms": ["Linux", "Windows", "macOS"],
        "detection_tips": [
            "Monitor for unusual scanning patterns",
            "Watch for port enumeration attempts",
            "Track new source IPs"
        ]
    }
}


class MITREMapper:
    """Maps detected attacks to MITRE ATT&CK Framework."""

    def __init__(self):
        self.database = MITRE_DATABASE

    def map_attack(self, attack_type: str) -> Dict:
        entry = self.database.get(attack_type, self.database["Unknown"])
        return {
            "tactic": {
                "id": entry["tactic_id"],
                "name": entry["tactic_name"]
            },
            "technique": {
                "id": entry["technique_id"],
                "name": entry["technique_name"],
                "sub_techniques": entry["sub_techniques"]
            },
            "kill_chain_phases": entry["kill_chain"],
            "severity_base_score": entry["severity_base"],
            "description": entry["description"],
            "mitigations": entry["mitigations"],
            "data_sources": entry["data_sources"],
            "platforms": entry["platforms"],
            "detection_tips": entry["detection_tips"]
        }

    def get_kill_chain_position(self, attack_type: str) -> Dict:
        entry = self.database.get(attack_type, self.database["Unknown"])
        phases = ["reconnaissance", "weaponization", "delivery", "exploitation",
                  "installation", "c2", "exfiltration"]
        attack_phases = entry["kill_chain"]
        return {
            "phases": phases,
            "active_phases": attack_phases,
            "furthest_phase": attack_phases[-1] if attack_phases else "reconnaissance",
            "progression_percent": round(
                (phases.index(attack_phases[-1]) + 1) / len(phases) * 100
            ) if attack_phases and attack_phases[-1] in phases else 0
        }

    def get_related_techniques(self, attack_type: str) -> List[Dict]:
        entry = self.database.get(attack_type, self.database["Unknown"])
        tactic_id = entry["tactic_id"]
        related = []
        for name, data in self.database.items():
            if name != attack_type and data["tactic_id"] == tactic_id:
                related.append({
                    "attack_type": name,
                    "technique_id": data["technique_id"],
                    "technique_name": data["technique_name"]
                })
        return related

    def generate_full_mapping(self, attack_type: str, confidence: float = 0.5) -> Dict:
        mapping = self.map_attack(attack_type)
        kill_chain = self.get_kill_chain_position(attack_type)
        related = self.get_related_techniques(attack_type)
        adjusted_severity = round(mapping["severity_base_score"] * confidence, 1)
        return {
            "attack_type": attack_type,
            "mitre_mapping": mapping,
            "kill_chain": kill_chain,
            "related_techniques": related,
            "adjusted_severity": adjusted_severity,
            "risk_level": (
                "CRITICAL" if adjusted_severity >= 9.0 else
                "HIGH" if adjusted_severity >= 7.0 else
                "MEDIUM" if adjusted_severity >= 4.0 else
                "LOW"
            )
        }

    def get_coverage_report(self) -> Dict:
        tactics = {}
        for name, data in self.database.items():
            tid = data["tactic_id"]
            if tid not in tactics:
                tactics[tid] = {"name": data["tactic_name"], "techniques": []}
            tactics[tid]["techniques"].append({
                "attack_type": name,
                "technique_id": data["technique_id"],
                "technique_name": data["technique_name"]
            })
        return {
            "total_attack_types": len(self.database),
            "total_tactics_covered": len(tactics),
            "total_mitigations": len(set(
                m["id"] for d in self.database.values() for m in d["mitigations"]
            )),
            "tactics": tactics
        }
