# ZeroCyber-SLM v3.0
### Enterprise AI Cybersecurity Platform — 100% Offline

> The first AI cybersecurity platform that NEVER leaves your network.

[![GitHub](https://img.shields.io/badge/GitHub-ZeroCyber--SLM-blue?logo=github)](https://github.com/rOOtsystem2010/ZeroCyber-SLM)
[![HuggingFace](https://img.shields.io/badge/HuggingFace-Rootsystem2101-yellow?logo=huggingface)](https://huggingface.co/Rootsystem2101)
[![Python](https://img.shields.io/badge/Python-3.10+-green?logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-red)](LICENSE)

---

## What Makes It Unique

| Feature | ZeroCyber-SLM | CrowdStrike | SentinelOne | Darktrace |
|---------|:---:|:---:|:---:|:---:|
| 100% Offline | ✅ | ❌ | ❌ | ❌ |
| Zero Data Exfiltration | ✅ | ❌ | ❌ | ❌ |
| Attack Narrative Generation | ✅ | ❌ | ❌ | ❌ |
| Runs on Laptop | ✅ | ❌ | ❌ | ❌ |
| Free / No Subscription | ✅ | ❌ $40K+/yr | ❌ $30K+/yr | ❌ $30K+/yr |
| AI Forensics Copilot | ✅ | ❌ | ❌ | ❌ |

---

## Features
- **ZeroCyber-SLM AI Model** — custom-trained cybersecurity model via Ollama (fully offline)
- **29 Detection Rules** covering OWASP Top 10
- **MITRE ATT&CK Mapping** — 18+ techniques across 14 attack types
- **Attack Narrative Generation** — AI converts attack events into human-readable incident reports
- **Autonomous Threat Hunting** — proactively hunts processes, network, persistence mechanisms
- **Digital Forensics Copilot** — offline file/log analysis with entropy, hashes, strings
- **REST API v3.0** — 30+ endpoints, CORS-enabled, Flask-based
- **Immutable Audit Chain** — SHA3-512 quantum-resistant tamper-proof logging
- **Cross-Platform Immune System** — Windows (netsh) & Linux (UFW/iptables) firewall integration
- **Web Dashboard** — real-time threat monitoring with charts

---

## AI Model

The core intelligence is powered by **ZeroCyber-SLM** — a custom Small Language Model specifically trained for cybersecurity threat analysis.

- Platform: [HuggingFace — Rootsystem2101](https://huggingface.co/Rootsystem2101)
- Runtime: [Ollama](https://ollama.ai) (local inference, no internet required)
- Size: ~4.4GB
- Specialization: Attack detection, forensic analysis, threat narration

---

## Quick Start

### Prerequisites
- Python 3.10+
- [Ollama](https://ollama.ai) installed and running
- ZeroCyber-SLM model loaded in Ollama

### Install
```bash
git clone https://github.com/rOOtsystem2010/ZeroCyber-SLM
cd ZeroCyber-SLM
pip install -r requirements_complete.txt
```

### Run
```bash
python api_server.py
```
Then open: **http://localhost:5000/**

### Test (22 real attack payloads)
```bash
python test_zerocyber.py
```

---

## Detection Results

| Attack Type | Detection Rate | Confidence | Method |
|-------------|:---:|:---:|---|
| SQL Injection (4 variants) | 100% | 84–93% | ZeroCyber-SLM + Rules |
| XSS (3 variants) | 100% | 91–93% | ZeroCyber-SLM + Rules |
| Command Injection (4 variants) | 100% | 80–93% | ZeroCyber-SLM + Rules |
| Path Traversal (3 variants) | 100% | 81–90% | ZeroCyber-SLM + Rules |
| SSRF | 100% | 82–87% | ZeroCyber-SLM + Rules |
| RCE — PHP / Python | 100% | 90–95% | ZeroCyber-SLM + Rules |
| Evasion (Base64, URL, Case) | 100% | 30–93% | ZeroCyber-SLM |

**Overall: 22/22 real-world attack payloads detected — 100%**

---

## API Endpoints

```
GET  /                           Web Dashboard
GET  /api/v3/health              System health check
POST /api/v3/analyze             Analyze payload for threats
GET  /api/v3/threats             List all detected threats
POST /api/v3/mitre/map           Map to MITRE ATT&CK framework
POST /api/v3/narrative           Generate AI attack narrative report
POST /api/v3/hunt                Run autonomous threat hunt
POST /api/v3/forensics/analyze-file   Analyze suspicious file
POST /api/v3/forensics/chat      Chat with forensics AI
POST /api/v3/ips/block           Block IP address
GET  /api/v3/ips/blocked         List blocked IPs
GET  /api/v3/chain/verify        Verify audit chain integrity
POST /api/v3/chat                Chat with ZeroCyber-SLM
```

---

## Architecture

```
zerocyber_complete.py    ← Main entry point (all modules)
api_server.py            ← Flask REST API (30+ endpoints)
zerocyber_engine.py      ← Hybrid AI + rule detection engine
persistence.py           ← SQLite database (9 tables)
mitre_mapper.py          ← MITRE ATT&CK mapping database
narrative_generator.py   ← AI attack story generation
threat_hunter.py         ← Autonomous threat hunting
forensics_copilot.py     ← Digital forensics analysis
immune_system.py         ← Cross-platform IP/process blocking
integrations.py          ← SIEM / Slack / Telegram / Webhook
dashboard.html           ← Web dashboard (real-time)
test_zerocyber.py        ← Full attack test suite
```

---

## Target Markets
- **Military & Defense** — classified/air-gapped networks
- **Healthcare** — HIPAA-compliant environments
- **Finance** — isolated trading networks
- **Government** — classified operations
- **Regulated Industries** — GDPR, NIS2, compliance-heavy

---

## Links
- GitHub: https://github.com/rOOtsystem2010/ZeroCyber-SLM
- HuggingFace: https://huggingface.co/Rootsystem2101

---

Built by **Rootsystem2101** with ZeroCyber-SLM + Claude AI
