"""Email alert delivery"""

import smtplib
from email.mime.text import MIMEText
from typing import Any

from provchain.data.models import Alert


class EmailAlerter:
    """Send alerts via email"""

    def __init__(
        self,
        smtp_server: str,
        smtp_port: int,
        username: str,
        password: str,
        from_email: str,
        to_email: str,
    ):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_email = from_email
        self.to_email = to_email

    def send(self, alert: Alert) -> None:
        """Send alert via email"""
        subject = f"[ProvChain Alert] {alert.severity.value.upper()}: {alert.title}"
        body = f"""
ProvChain Security Alert

Package: {alert.package}
Type: {alert.alert_type}
Severity: {alert.severity.value}
Timestamp: {alert.timestamp.isoformat()}

Description:
{alert.description}

Evidence:
{alert.evidence}

Recommended Action:
{alert.recommended_action or "Review the alert and take appropriate action"}
"""

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = self.from_email
        msg["To"] = self.to_email

        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)
        except Exception:
            # Log error
            pass

