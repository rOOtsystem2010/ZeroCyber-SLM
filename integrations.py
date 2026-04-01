# ===== integrations.py =====
"""
ZeroCyber Integration Layer
Connect to SIEM, Slack, Telegram, Email, and custom webhooks.
"""

import requests
import json
from datetime import datetime
from typing import Dict, List, Optional


class SIEMIntegration:
    """Send events to SIEM systems (Splunk, ELK, QRadar, etc.)"""

    def __init__(self, siem_url: str = "", siem_token: str = ""):
        self.siem_url = siem_url
        self.siem_token = siem_token
        self.enabled = bool(siem_url)

    def send_event(self, event: Dict) -> bool:
        if not self.enabled:
            return False
        try:
            headers = {"Authorization": f"Bearer {self.siem_token}"}
            requests.post(self.siem_url, json=event, headers=headers, timeout=10)
            return True
        except Exception:
            return False


class SlackIntegration:
    """Send alerts to Slack"""

    def __init__(self, webhook_url: str = ""):
        self.webhook_url = webhook_url
        self.enabled = bool(webhook_url)

    def send_alert(self, threat: Dict, severity: str = "warning") -> bool:
        if not self.enabled:
            return False

        color_map = {"CRITICAL": "#FF0000", "HIGH": "#FF8C00", "MEDIUM": "#FFD700", "LOW": "#00AA00"}
        color = color_map.get(severity, "#808080")

        payload = {
            "attachments": [{
                "color": color,
                "title": f"🚨 {threat.get('attack_type', 'Unknown Attack')}",
                "fields": [
                    {"title": "Severity", "value": severity, "short": True},
                    {"title": "Source IP", "value": threat.get("source_ip", "unknown"), "short": True},
                    {"title": "Confidence", "value": f"{threat.get('confidence', 0) * 100:.0f}%", "short": True},
                    {"title": "Action", "value": threat.get("action", "LOG"), "short": True},
                    {"title": "Signature", "value": threat.get("signature", "")[:100], "short": False}
                ],
                "ts": int(datetime.now().timestamp())
            }]
        }

        try:
            requests.post(self.webhook_url, json=payload, timeout=10)
            return True
        except Exception:
            return False


class TelegramIntegration:
    """Send alerts to Telegram"""

    def __init__(self, bot_token: str = "", chat_id: str = ""):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.enabled = bool(bot_token and chat_id)

    def send_alert(self, threat: Dict) -> bool:
        if not self.enabled:
            return False

        message = (
            f"🚨 <b>{threat.get('attack_type', 'Unknown')}</b>\n"
            f"🔴 Severity: <b>{threat.get('classification', 'UNKNOWN')}</b>\n"
            f"📍 Source: <code>{threat.get('source_ip', 'unknown')}</code>\n"
            f"📊 Confidence: <b>{threat.get('confidence', 0) * 100:.0f}%</b>\n"
            f"⚡ Action: <code>{threat.get('action', 'LOG')}</code>\n"
            f"🔍 Signature: <code>{threat.get('signature', '')[:80]}</code>"
        )

        try:
            url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
            requests.post(
                url,
                json={"chat_id": self.chat_id, "text": message, "parse_mode": "HTML"},
                timeout=10
            )
            return True
        except Exception:
            return False


class WebhookIntegration:
    """Send events to custom webhooks"""

    def __init__(self, webhook_urls: List[str] = None):
        self.webhook_urls = webhook_urls or []
        self.enabled = len(self.webhook_urls) > 0

    def send_event(self, event: Dict) -> bool:
        if not self.enabled:
            return False

        success_count = 0
        for url in self.webhook_urls:
            try:
                requests.post(url, json=event, timeout=10)
                success_count += 1
            except Exception:
                continue
        return success_count > 0


class EmailIntegration:
    """Send alerts via email (requires SMTP setup)"""

    def __init__(self, smtp_server: str = "", smtp_port: int = 587,
                 from_email: str = "", from_password: str = "", to_emails: List[str] = None):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.from_email = from_email
        self.from_password = from_password
        self.to_emails = to_emails or []
        self.enabled = bool(smtp_server and from_email)

    def send_alert(self, threat: Dict, subject: str = "ZeroCyber Alert") -> bool:
        if not self.enabled or not self.to_emails:
            return False

        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart

            msg = MIMEMultipart()
            msg['From'] = self.from_email
            msg['To'] = ', '.join(self.to_emails)
            msg['Subject'] = f"{subject}: {threat.get('attack_type', 'Unknown')}"

            body = (
                f"Threat Alert\n"
                f"============\n\n"
                f"Attack Type: {threat.get('attack_type', 'Unknown')}\n"
                f"Severity: {threat.get('classification', 'UNKNOWN')}\n"
                f"Source IP: {threat.get('source_ip', 'unknown')}\n"
                f"Confidence: {threat.get('confidence', 0) * 100:.0f}%\n"
                f"Action: {threat.get('action', 'LOG')}\n"
                f"Signature: {threat.get('signature', '')}\n"
                f"Timestamp: {threat.get('timestamp', 'unknown')}\n"
            )

            msg.attach(MIMEText(body, 'plain'))

            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.from_email, self.from_password)
                server.send_message(msg)
            return True
        except Exception:
            return False


class IntegrationManager:
    """Manage all integrations"""

    def __init__(self):
        self.siem = SIEMIntegration()
        self.slack = SlackIntegration()
        self.telegram = TelegramIntegration()
        self.webhooks = WebhookIntegration()
        self.email = EmailIntegration()

    def configure(self, config: Dict):
        """Configure integrations from dict"""
        if "siem" in config:
            self.siem = SIEMIntegration(config["siem"].get("url"), config["siem"].get("token"))
        if "slack" in config:
            self.slack = SlackIntegration(config["slack"].get("webhook_url"))
        if "telegram" in config:
            self.telegram = TelegramIntegration(config["telegram"].get("bot_token"), config["telegram"].get("chat_id"))
        if "webhooks" in config:
            self.webhooks = WebhookIntegration(config["webhooks"].get("urls", []))
        if "email" in config:
            self.email = EmailIntegration(
                config["email"].get("smtp_server"),
                config["email"].get("smtp_port", 587),
                config["email"].get("from_email"),
                config["email"].get("from_password"),
                config["email"].get("to_emails", [])
            )

    def broadcast_threat(self, threat: Dict) -> Dict:
        """Send threat to all configured integrations"""
        results = {
            "siem": self.siem.send_event(threat),
            "slack": self.slack.send_alert(threat, threat.get("classification", "LOW")),
            "telegram": self.telegram.send_alert(threat),
            "webhooks": self.webhooks.send_event(threat),
            "email": self.email.send_alert(threat)
        }
        return results

    def get_status(self) -> Dict:
        """Get integration status"""
        return {
            "siem": self.siem.enabled,
            "slack": self.slack.enabled,
            "telegram": self.telegram.enabled,
            "webhooks": self.webhooks.enabled,
            "email": self.email.enabled
        }
