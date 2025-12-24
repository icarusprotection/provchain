"""Webhook alert delivery"""

import httpx

from provchain.data.models import Alert


class WebhookAlerter:
    """Send alerts via webhook"""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send(self, alert: Alert) -> None:
        """Send alert to webhook"""
        payload = {
            "id": alert.id,
            "timestamp": alert.timestamp.isoformat(),
            "package": str(alert.package),
            "alert_type": alert.alert_type,
            "severity": alert.severity.value,
            "title": alert.title,
            "description": alert.description,
            "evidence": alert.evidence,
            "recommended_action": alert.recommended_action,
        }

        try:
            httpx.post(self.webhook_url, json=payload, timeout=10)
        except Exception:
            # Log error
            pass
