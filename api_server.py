# ===== api_server.py =====
"""
ZeroCyber REST API Server - Production v3.0
Enterprise-grade API for threat detection, forensics, hunting, and red team operations.
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from functools import wraps
import os
import json
import secrets
from datetime import datetime, timedelta
from io import BytesIO

# Import our modules
from persistence import ZeroCyberDB
from zerocyber_engine import ZeroCyberEngine
from mitre_mapper import MITREMapper
from narrative_generator import AttackNarrativeGenerator
from threat_hunter import ThreatHunter
from forensics_copilot import ForensicsCopilot

app = Flask(__name__)
CORS(app)

# Initialize core systems
db = ZeroCyberDB("zerocyber_production.db")
engine = ZeroCyberEngine()
mitre = MITREMapper()
narrator = AttackNarrativeGenerator(engine)
hunter = ThreatHunter(engine)
forensics = ForensicsCopilot(engine)

# Configuration
API_VERSION = "3.0"
AUTH_ENABLED = False  # Disabled for demo/testing


# ── Authentication Decorator ────────────────────────────────────
def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not AUTH_ENABLED:
            return f(*args, **kwargs)

        key = request.headers.get("X-API-Key")
        if not key:
            return jsonify({"error": "Missing X-API-Key header"}), 401

        api_key = db.validate_api_key(key)
        if not api_key:
            return jsonify({"error": "Invalid API key"}), 401

        # Check permissions
        if api_key["permissions"] == "read" and request.method != "GET":
            return jsonify({"error": "Read-only API key"}), 403

        request.api_key = api_key
        return f(*args, **kwargs)
    return decorated


# ── Dashboard Route ────────────────────────────────────────────
@app.route("/", methods=["GET"])
def serve_dashboard():
    """Serve the web dashboard."""
    return send_file("dashboard.html")


# ── Health & Info Endpoints ────────────────────────────────────
@app.route("/api/v3/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "version": API_VERSION,
        "engine": "ZeroCyber-SLM v3.0",
        "ollama": engine.ollama_available,
        "timestamp": datetime.now().isoformat()
    })


@app.route("/api/v3/info", methods=["GET"])
def info():
    stats = db.get_dashboard_stats()
    return jsonify({
        "product": "ZeroCyber-SLM",
        "version": API_VERSION,
        "description": "Enterprise AI cybersecurity platform with offline threat detection and forensics",
        "features": [
            "Real-time threat detection (hybrid AI + rules)",
            "MITRE ATT&CK mapping",
            "Attack narrative generation",
            "Autonomous threat hunting",
            "Digital forensics analysis",
            "100% offline operation",
            "REST API",
            "Persistent audit chain"
        ],
        "capabilities": {
            "ollama_model": "ZeroCyber-SLM (4.4GB)",
            "detection_rules": len(engine.rules),
            "mitre_coverage": mitre.get_coverage_report()["total_attack_types"],
            "databases": ["Threats", "Audit Chain", "Blocked IPs", "Forensic Reports", "Hunt Sessions"]
        },
        "stats": stats,
        "timestamp": datetime.now().isoformat()
    })


# ── Threat Detection Endpoints ──────────────────────────────────
@app.route("/api/v3/analyze", methods=["POST"])
@require_api_key
def analyze_threat():
    """Analyze a payload for threats."""
    data = request.get_json() or {}
    payload = data.get("payload", "")
    source_ip = data.get("source_ip", request.remote_addr)

    if not payload:
        return jsonify({"error": "Missing payload field"}), 400

    # Analyze
    result = engine.analyze(payload, source_ip)

    # Add MITRE mapping
    mitre_map = mitre.generate_full_mapping(result["attack_type"], result["confidence"])
    result["mitre_mapping"] = mitre_map

    # Save to database
    threat_id = db.save_threat({
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
        "mitre_technique": mitre_map["mitre_mapping"]["technique"]["name"],
        "processing_time_ms": result["processing_time_ms"],
        "raw_payload_hash": result["payload_hash"]
    })

    result["threat_id"] = threat_id
    return jsonify(result)


@app.route("/api/v3/threats", methods=["GET"])
@require_api_key
def list_threats():
    """List detected threats with filtering."""
    limit = min(int(request.args.get("limit", 100)), 1000)
    offset = int(request.args.get("offset", 0))
    ip = request.args.get("ip")
    attack_type = request.args.get("type")
    classification = request.args.get("classification")

    threats = db.get_threats(limit, offset, ip, attack_type, classification)
    stats = db.get_threat_stats()

    return jsonify({
        "threats": threats,
        "count": len(threats),
        "stats": stats,
        "pagination": {"limit": limit, "offset": offset}
    })


@app.route("/api/v3/threats/<int:threat_id>", methods=["GET"])
@require_api_key
def get_threat(threat_id):
    """Get specific threat details."""
    threats = db.get_threats(limit=1, offset=threat_id - 1)
    if not threats:
        return jsonify({"error": "Threat not found"}), 404
    return jsonify(threats[0])


# ── MITRE ATT&CK Endpoints ─────────────────────────────────────
@app.route("/api/v3/mitre/map", methods=["POST"])
@require_api_key
def mitre_map():
    """Map attack to MITRE ATT&CK framework."""
    data = request.get_json() or {}
    attack_type = data.get("attack_type", "Unknown")
    confidence = float(data.get("confidence", 0.5))

    mapping = mitre.generate_full_mapping(attack_type, confidence)
    return jsonify(mapping)


@app.route("/api/v3/mitre/coverage", methods=["GET"])
@require_api_key
def mitre_coverage():
    """Get MITRE ATT&CK coverage report."""
    return jsonify(mitre.get_coverage_report())


# ── Attack Narrative Endpoints ─────────────────────────────────
@app.route("/api/v3/narrative", methods=["POST"])
@require_api_key
def generate_narrative():
    """Generate attack narrative from events."""
    data = request.get_json() or {}
    events = data.get("events", [])
    source_ip = data.get("source_ip", "unknown")

    if not events:
        return jsonify({"error": "Missing events field"}), 400

    narrative = narrator.build_narrative(events, source_ip)
    brief = narrator.generate_executive_brief(events, source_ip)

    return jsonify({
        "narrative": narrative,
        "executive_brief": brief,
        "event_count": len(events),
        "generated_at": datetime.now().isoformat()
    })


# ── Threat Hunt Endpoints ──────────────────────────────────────
@app.route("/api/v3/hunt", methods=["POST"])
@require_api_key
def run_threat_hunt():
    """Run autonomous threat hunting session."""
    hunt_result = hunter.run_full_hunt()

    # Save to database
    hunt_id = db.create_hunt_session(hunt_result["session_id"])
    db.update_hunt_session(
        hunt_result["session_id"],
        hunt_result["findings"],
        "completed"
    )

    return jsonify(hunt_result)


@app.route("/api/v3/hunt/<session_id>", methods=["GET"])
@require_api_key
def get_hunt_session(session_id):
    """Get threat hunt session results."""
    hunts = db.get_forensic_reports(limit=100)
    for h in hunts:
        if session_id in h.get("report_id", ""):
            return jsonify(json.loads(h["findings_json"]))
    return jsonify({"error": "Hunt session not found"}), 404


# ── Forensics Endpoints ────────────────────────────────────────
@app.route("/api/v3/forensics/analyze-log", methods=["POST"])
@require_api_key
def analyze_log():
    """Analyze log file for forensic evidence."""
    data = request.get_json() or {}
    file_path = data.get("file_path")

    if not file_path:
        return jsonify({"error": "Missing file_path field"}), 400

    result = forensics.analyze_log_file(file_path)

    # Save to database
    report_id = db.save_forensic_report({
        "type": "log_analysis",
        "title": f"Log Analysis: {os.path.basename(file_path)}",
        "findings": result,
        "severity": "HIGH" if len(result.get("attack_indicators", [])) > 5 else "MEDIUM"
    })

    return jsonify({**result, "report_id": report_id})


@app.route("/api/v3/forensics/analyze-file", methods=["POST"])
@require_api_key
def analyze_file():
    """Analyze file for malware indicators."""
    data = request.get_json() or {}
    file_path = data.get("file_path")

    if not file_path:
        return jsonify({"error": "Missing file_path field"}), 400

    result = forensics.analyze_file(file_path)

    # Save to database
    if "error" not in result:
        db.save_forensic_report({
            "type": "file_analysis",
            "title": f"File Analysis: {result.get('file_name', 'unknown')}",
            "findings": result,
            "severity": "CRITICAL" if result.get("is_high_entropy") else "MEDIUM"
        })

    return jsonify(result)


@app.route("/api/v3/forensics/timeline", methods=["POST"])
@require_api_key
def build_timeline():
    """Build forensic timeline from events."""
    data = request.get_json() or {}
    events = data.get("events", [])

    if not events:
        return jsonify({"error": "Missing events field"}), 400

    result = forensics.build_incident_timeline(events)
    return jsonify(result)


@app.route("/api/v3/forensics/chat", methods=["POST"])
@require_api_key
def forensics_chat():
    """Chat with forensics copilot."""
    data = request.get_json() or {}
    question = data.get("question", "")
    context = data.get("context", "")

    if not question:
        return jsonify({"error": "Missing question field"}), 400

    response = forensics.chat(question, context)
    return jsonify({
        "question": question,
        "response": response,
        "timestamp": datetime.now().isoformat()
    })


# ── IP Management Endpoints ────────────────────────────────────
@app.route("/api/v3/ips/block", methods=["POST"])
@require_api_key
def block_ip():
    """Block an IP address."""
    data = request.get_json() or {}
    ip = data.get("ip")
    reason = data.get("reason", "Manual block")
    duration_minutes = int(data.get("duration_minutes", 0))

    if not ip:
        return jsonify({"error": "Missing ip field"}), 400

    expires_at = None
    if duration_minutes > 0:
        expires_at = (datetime.now() + timedelta(minutes=duration_minutes)).isoformat()

    block_id = db.block_ip(ip, reason, expires_at)

    return jsonify({
        "block_id": block_id,
        "ip": ip,
        "reason": reason,
        "blocked_at": datetime.now().isoformat(),
        "expires_at": expires_at
    })


@app.route("/api/v3/ips/blocked", methods=["GET"])
@require_api_key
def list_blocked_ips():
    """List all blocked IPs."""
    blocked = db.get_blocked_ips()
    return jsonify({
        "blocked_ips": blocked,
        "count": len(blocked)
    })


@app.route("/api/v3/ips/check", methods=["GET"])
@require_api_key
def check_ip():
    """Check if IP is blocked."""
    ip = request.args.get("ip")
    if not ip:
        return jsonify({"error": "Missing ip parameter"}), 400

    is_blocked = db.is_blocked(ip)
    return jsonify({"ip": ip, "is_blocked": is_blocked})


# ── API Key Management Endpoints ───────────────────────────────
@app.route("/api/v3/keys/create", methods=["POST"])
@require_api_key
def create_api_key():
    """Create new API key (admin only)."""
    data = request.get_json() or {}
    name = data.get("name", "New Key")
    permissions = data.get("permissions", "read")

    raw_key = f"zc-{secrets.token_urlsafe(32)}"
    key_id = db.create_api_key(raw_key, name, permissions)

    return jsonify({
        "key_id": key_id,
        "raw_key": raw_key,
        "name": name,
        "permissions": permissions,
        "created_at": datetime.now().isoformat(),
        "warning": "Save this key securely. It will not be shown again."
    })


# ── Dashboard Endpoints ────────────────────────────────────────
@app.route("/api/v3/dashboard", methods=["GET"])
@require_api_key
def dashboard():
    """Get dashboard statistics."""
    stats = db.get_dashboard_stats()
    return jsonify(stats)


@app.route("/api/v3/dashboard/export", methods=["GET"])
@require_api_key
def export_dashboard():
    """Export dashboard as JSON."""
    stats = db.get_dashboard_stats()
    threats = db.get_threats(limit=1000)
    chain = db.get_chain(limit=100)

    export_data = {
        "exported_at": datetime.now().isoformat(),
        "dashboard_stats": stats,
        "threats": threats,
        "audit_chain": chain
    }

    json_bytes = json.dumps(export_data, indent=2, ensure_ascii=False).encode()
    return send_file(
        BytesIO(json_bytes),
        mimetype="application/json",
        as_attachment=True,
        download_name=f"zerocyber_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )


# ── Audit Chain Endpoints ──────────────────────────────────────
@app.route("/api/v3/chain/verify", methods=["GET"])
@require_api_key
def verify_chain():
    """Verify blockchain integrity."""
    result = db.verify_chain_integrity()
    return jsonify(result)


@app.route("/api/v3/chain/blocks", methods=["GET"])
@require_api_key
def get_chain_blocks():
    """Get blockchain blocks."""
    limit = min(int(request.args.get("limit", 100)), 1000)
    blocks = db.get_chain(limit)
    return jsonify({"blocks": blocks, "count": len(blocks)})


# ── AI Chat Endpoints ──────────────────────────────────────────
@app.route("/api/v3/chat", methods=["POST"])
@require_api_key
def ai_chat():
    """Chat with ZeroCyber AI."""
    data = request.get_json() or {}
    message = data.get("message", "")
    context = data.get("context", "")

    if not message:
        return jsonify({"error": "Missing message field"}), 400

    if not engine.ollama_available:
        return jsonify({"error": "ZeroCyber-SLM model not available"}), 503

    response = engine.chat(message, context)

    return jsonify({
        "query": message,
        "response": response,
        "model": "ZeroCyber-SLM",
        "timestamp": datetime.now().isoformat()
    })


# ── Error Handlers ─────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500


# ── Startup ────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    print("\n" + "="*80)
    print("[API] ZeroCyber REST API Server v3.0")
    print("="*80)
    print(f"[API] Listening on http://0.0.0.0:5000")
    print(f"[AI]  ZeroCyber-SLM: {'CONNECTED' if engine.ollama_available else 'OFFLINE (rules only)'}")
    print(f"[DB]  SQLite persistence: ACTIVE")
    print(f"[Rules] {len(engine.rules)} detection rules loaded")
    print("="*80 + "\n")

    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
