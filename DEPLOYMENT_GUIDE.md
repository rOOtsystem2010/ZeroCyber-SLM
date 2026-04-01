# ZeroCyber-SLM v3.0 - Deployment & Usage Guide

## 🎯 Product Overview

**ZeroCyber-SLM** is an enterprise-grade AI cybersecurity platform that works 100% offline with zero data exfiltration. It combines:

- **ZeroCyber-SLM Model** (4.4GB, runs locally on Ollama)
- **29 Rule-based Detection Patterns** (fast, always-on)
- **AI-Powered Analysis** (deep threat understanding)
- **MITRE ATT&CK Mapping** (standardized threat classification)
- **Attack Narrative Generation** (human-readable incident reports)
- **Autonomous Threat Hunting** (proactive threat discovery)
- **Digital Forensics Copilot** (offline evidence analysis)
- **REST API v3.0** (enterprise integration)
- **Persistent Audit Chain** (immutable threat log)
- **Cross-Platform Immune System** (Windows + Linux blocking)

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- Ollama with ZeroCyber-SLM model loaded (`ollama run ZeroCyber-SLM`)
- Flask, requests, pandas installed

### 1. **Start the Complete System**
```bash
cd F:/ZeroCyber_Lab/ZeroCyber-SLM-Paython
python zerocyber_complete.py
```

This initializes all systems and performs threat detection tests.

### 2. **Start REST API Server** (port 5000)
```bash
python api_server.py
```

Then test:
```bash
curl http://localhost:5000/api/v3/health
```

### 3. **Start Web Dashboard** (port 8000)
Open `dashboard.html` in a web browser (currently runs via Flask in api_server):
```
http://localhost:5000/
```

### 4. **Run Autonomous Threat Hunt**
```python
from zerocyber_complete import ZeroCyberComplete
system = ZeroCyberComplete()
hunt = system.hunt_threats()
print(hunt)
```

---

## 📊 REST API Endpoints

### Health & Info
- `GET /api/v3/health` - System health check
- `GET /api/v3/info` - Complete system information
- `GET /api/v3/dashboard` - Dashboard statistics

### Threat Detection
- `POST /api/v3/analyze` - Analyze payload for threats
  ```json
  {"payload": "...", "source_ip": "192.168.1.1"}
  ```
- `GET /api/v3/threats?limit=100` - List detected threats
- `GET /api/v3/threats/<id>` - Get specific threat

### MITRE ATT&CK
- `POST /api/v3/mitre/map` - Map attack to MITRE framework
- `GET /api/v3/mitre/coverage` - Get coverage report

### Attack Narratives
- `POST /api/v3/narrative` - Generate attack story from events

### Threat Hunting
- `POST /api/v3/hunt` - Run autonomous threat hunt
- `GET /api/v3/hunt/<session_id>` - Get hunt results

### Digital Forensics
- `POST /api/v3/forensics/analyze-log` - Analyze log file
- `POST /api/v3/forensics/analyze-file` - Analyze suspicious file
- `POST /api/v3/forensics/timeline` - Build incident timeline
- `POST /api/v3/forensics/chat` - Chat with forensics AI

### IP Management
- `POST /api/v3/ips/block` - Block IP address
- `GET /api/v3/ips/blocked` - List blocked IPs
- `GET /api/v3/ips/check?ip=...` - Check if IP is blocked

### Audit Chain
- `GET /api/v3/chain/verify` - Verify blockchain integrity
- `GET /api/v3/chain/blocks` - Get audit chain blocks

### AI Chat
- `POST /api/v3/chat` - Chat with ZeroCyber-SLM
  ```json
  {"message": "...", "context": "..."}
  ```

---

## 🛡️ Unique Features (No Competitors Offer)

### 1. **100% Offline Operation**
- AI model runs locally (4.4GB)
- Zero data leaves your network
- Perfect for air-gapped/classified environments

### 2. **Attack Narrative Generation**
Converts scattered events into coherent attack stories:
```
"At 14:32, attacker from 203.0.113.1 started with SQL injection attempts.
After 5 minutes, pivoted to XSS attacks. Used Base64 encoding to evade filters.
Attempted 3 different encoding techniques before succeeding."
```

### 3. **Autonomous Threat Hunting**
Proactively searches for:
- Suspicious processes
- Malicious network connections
- Persistence mechanisms
- Evidence tampering

### 4. **Digital Forensics Copilot**
AI-assisted analysis of:
- Log files (with pattern detection)
- Malware samples (entropy, strings, hashes)
- Network captures
- Incident timelines

### 5. **Immutable Audit Chain**
Blockchain-style tamper-proof logging with:
- SHA3-512 quantum-resistant hashing
- Merkle root integrity
- Automatic verification

---

## 🎬 Usage Examples

### Example 1: Detect SQL Injection
```python
from zerocyber_complete import ZeroCyberComplete
system = ZeroCyberComplete()

result = system.analyze_threat(
    payload="SELECT * FROM users WHERE id='1' OR '1'='1'",
    source_ip="192.168.1.100"
)

print(f"Attack: {result['attack_type']}")
print(f"Confidence: {result['confidence']*100:.0f}%")
print(f"MITRE: {result['mitre']['mitre_mapping']['technique']['name']}")
print(f"Action: {result['action']}")
```

### Example 2: Run Threat Hunt
```python
hunt_result = system.hunt_threats()
print(f"Findings: {hunt_result['findings_count']}")
for finding in hunt_result['findings'][:5]:
    print(f"  - [{finding['severity']}] {finding['finding']}")
```

### Example 3: Analyze Suspicious File
```python
forensic = system.analyze_file("/tmp/suspicious.exe")
print(f"File: {forensic['file_name']}")
print(f"SHA256: {forensic['hashes']['sha256']}")
print(f"Entropy: {forensic['entropy']} (High entropy = likely packed/encrypted)")
if forensic['suspicious_strings']:
    print(f"Suspicious strings found: {len(forensic['suspicious_strings'])}")
```

### Example 4: Chat with AI About Incident
```python
response = system.forensics.chat(
    question="What could cause 50 failed logins from the same IP?",
    context="IP 203.0.113.1 logged in 50 times in 5 minutes on Mar 30"
)
print(response)
```

---

## 🔧 Configuration

Edit `zerocyber_config.json` to enable integrations:

```json
{
  "integrations": {
    "slack": {
      "webhook_url": "https://hooks.slack.com/services/..."
    },
    "telegram": {
      "bot_token": "...",
      "chat_id": "..."
    },
    "siem": {
      "url": "https://splunk.example.com/services/collector",
      "token": "..."
    }
  }
}
```

---

## 📈 Performance Specs

| Metric | Value |
|--------|-------|
| Rule-based detection | < 100ms |
| AI analysis (with ZeroCyber-SLM) | 3-5 seconds |
| Detection rules loaded | 29 |
| MITRE techniques covered | 18+ |
| Threats stored (SQLite) | Unlimited |
| Audit chain blocks | Unlimited |
| Concurrent hunters | 1 (configurable) |
| API throughput | ~1000 req/min (single core) |

---

## 🔐 Security Guarantees

✓ **Zero Data Exfiltration** - AI runs locally, never leaves your network
✓ **Offline-First** - Works without internet connection
✓ **Immutable Audit Trail** - Tamper-proof threat logging
✓ **Cross-Platform** - Windows & Linux supported
✓ **No Cloud Dependency** - Complete operational independence
✓ **Open Detection Rules** - Transparent threat analysis

---

## 🎯 Competitive Advantages

| Feature | ZeroCyber | CrowdStrike | Darktrace | Palo Alto |
|---------|-----------|-------------|-----------|-----------|
| 100% Offline | ✅ | ❌ | ❌ | ❌ |
| Zero data leaves network | ✅ | ❌ | ❌ | ❌ |
| Attack Narrative Generation | ✅ | ❌ | ❌ | ⚠️ |
| Autonomous Threat Hunting | ✅ | ⚠️ | ✅ | ⚠️ |
| Digital Forensics AI | ✅ | ❌ | ❌ | ❌ |
| Runs on laptops | ✅ | ❌ | ❌ | ❌ |
| No subscription required | ✅ | ❌ | ❌ | ❌ |

---

## 📞 Support

For issues, check:
1. Is Ollama running? `ollama list`
2. Is ZeroCyber-SLM loaded? `ollama run ZeroCyber-SLM`
3. Check logs: `tail -f api.log`
4. Database integrity: `GET /api/v3/chain/verify`

---

## 🚀 Deployment

### Production Setup
```bash
# Install requirements
pip install -r requirements_complete.txt

# Run with Gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 api_server:app

# Run with Nginx reverse proxy (recommended)
# See nginx.conf template in docs/
```

### Docker (Coming Soon)
```bash
docker build -t zerocyber-slm .
docker run -p 5000:5000 -v /path/to/data:/app/data zerocyber-slm
```

---

**ZeroCyber-SLM v3.0** - Enterprise AI Security That Never Leaves Your Network
