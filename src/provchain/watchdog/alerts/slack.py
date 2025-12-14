"""Slack webhook integration"""

import json
from typing import Any

import httpx

from provchain.data.models import Alert


class SlackAlerter:
    """Send alerts to Slack via webhook"""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send(self, alert: Alert) -> None:
        """Send alert to Slack"""
        # Map severity to Slack color
        color_map = {
            "critical": "danger",
            "high": "warning",
            "medium": "warning",
            "low": "good",
            "unknown": "#808080",
        }

        payload = {
            "attachments": [
                {
                    "color": color_map.get(alert.severity.value, "#808080"),
                    "title": alert.title,
                    "fields": [
                        {"title": "Package", "value": str(alert.package), "short": True},
                        {"title": "Severity", "value": alert.severity.value.upper(), "short": True},
                        {"title": "Type", "value": alert.alert_type, "short": True},
                        {"title": "Description", "value": alert.description, "short": False},
                    ],
                    "footer": "ProvChain",
                    "ts": int(alert.timestamp.timestamp()),
                }
            ]
        }

        if alert.recommended_action:
            payload["attachments"][0]["fields"].append(
                {"title": "Recommended Action", "value": alert.recommended_action, "short": False}
            )

        try:
            httpx.post(self.webhook_url, json=payload, timeout=10)
        except Exception:
            # Log error
            pass

