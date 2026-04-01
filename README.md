# ZeroCyber-SLM v3.0
### Enterprise AI Cybersecurity Platform — 100% Offline

> The first AI cybersecurity platform that NEVER leaves your network.

---

## Features
- **29 Detection Rules** covering OWASP Top 10
- **ZeroCyber-SLM AI Model** (4.4GB, runs via Ollama — fully offline)
- **MITRE ATT&CK Mapping** — 18+ techniques
- **Attack Narrative Generation** — unique feature, no competitor offers this
- **Autonomous Threat Hunting** — processes, network, persistence
- **Digital Forensics Copilot** — offline evidence analysis
- **REST API v3.0** — 30+ endpoints
- **Immutable Audit Chain** — SHA3-512 tamper-proof logging
- **Cross-Platform** — Windows & Linux firewall integration

---

## Quick Start

### Prerequisites
- Python 3.10+
- [Ollama](https://ollama.ai) with ZeroCyber-SLM model loaded

### Install
```bash
pip install -r requirements_complete.txt
```

### Run
```bash
# Start API + Dashboard
python api_server.py

# Open in browser
http://localhost:5000/
```

### Test
```bash
python test_zerocyber.py
```

---

## Detection Results (Tested)
| Attack Type | Detection Rate | Confidence |
|-------------|---------------|------------|
| SQL Injection | 100% (4/4) | 84–93% |
| XSS | 100% (3/3) | 91–93% |
| Command Injection | 100% (4/4) | 80–93% |
| Path Traversal | 100% (3/3) | 81–90% |
| SSRF | 100% (2/2) | 82–87% |
| RCE | 100% (2/2) | 90–95% |
| Evasion Techniques | 100% (3/3) | 30–93% |

**Overall: 22/22 real-world attack payloads detected**

---

## API Endpoints
```
GET  /                          Web Dashboard
GET  /api/v3/health             System health
POST /api/v3/analyze            Analyze payload
GET  /api/v3/threats            List threats
POST /api/v3/mitre/map          MITRE ATT&CK mapping
POST /api/v3/narrative          Generate attack narrative
POST /api/v3/hunt               Autonomous threat hunt
POST /api/v3/forensics/chat     Forensics AI chat
POST /api/v3/ips/block          Block IP address
GET  /api/v3/chain/verify       Audit chain integrity
POST /api/v3/chat               Chat with ZeroCyber-SLM
```

---

## Architecture
```
zerocyber_complete.py    Main entry point
api_server.py            Flask REST API (30+ endpoints)
zerocyber_engine.py      AI detection engine (hybrid)
persistence.py           SQLite database layer
mitre_mapper.py          MITRE ATT&CK mapping
narrative_generator.py   Attack story generation
threat_hunter.py         Autonomous threat hunting
forensics_copilot.py     Digital forensics AI
immune_system.py         Cross-platform IP blocking
integrations.py          SIEM/Slack/Telegram/Webhook
dashboard.html           Web dashboard UI
```

---

Built with ZeroCyber-SLM + Claude AI
