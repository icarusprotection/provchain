"""Tests for alert handlers"""

from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

import pytest
import httpx

from provchain.watchdog.alerts.email import EmailAlerter
from provchain.watchdog.alerts.slack import SlackAlerter
from provchain.watchdog.alerts.webhook import WebhookAlerter
from provchain.data.models import Alert, PackageIdentifier, RiskLevel


@pytest.fixture
def sample_alert():
    """Sample alert for testing"""
    return Alert(
        id="test-alert-1",
        timestamp=datetime.now(timezone.utc),
        package=PackageIdentifier(ecosystem="pypi", name="test-package", version="1.0.0"),
        alert_type="cve",
        severity=RiskLevel.HIGH,
        title="Test Alert",
        description="This is a test alert",
        evidence={"key1": "Evidence 1", "key2": "Evidence 2"},
        recommended_action="Review and update package",
    )


class TestEmailAlerter:
    """Test cases for EmailAlerter"""

    def test_email_alerter_init(self):
        """Test EmailAlerter initialization"""
        alerter = EmailAlerter(
            smtp_server="smtp.example.com",
            smtp_port=587,
            username="user@example.com",
            password="password",
            from_email="from@example.com",
            to_email="to@example.com",
        )
        assert alerter.smtp_server == "smtp.example.com"
        assert alerter.smtp_port == 587
        assert alerter.username == "user@example.com"
        assert alerter.from_email == "from@example.com"
        assert alerter.to_email == "to@example.com"

    def test_email_alerter_send_success(self, sample_alert):
        """Test successful email alert sending"""
        alerter = EmailAlerter(
            smtp_server="smtp.example.com",
            smtp_port=587,
            username="user@example.com",
            password="password",
            from_email="from@example.com",
            to_email="to@example.com",
        )
        
        with patch('smtplib.SMTP') as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__.return_value = mock_server
            mock_smtp.return_value.__exit__.return_value = None
            
            alerter.send(sample_alert)
            
            mock_smtp.assert_called_once_with("smtp.example.com", 587)
            mock_server.starttls.assert_called_once()
            mock_server.login.assert_called_once_with("user@example.com", "password")
            mock_server.send_message.assert_called_once()

    def test_email_alerter_send_error_handling(self, sample_alert):
        """Test email alert error handling"""
        alerter = EmailAlerter(
            smtp_server="smtp.example.com",
            smtp_port=587,
            username="user@example.com",
            password="password",
            from_email="from@example.com",
            to_email="to@example.com",
        )
        
        with patch('smtplib.SMTP', side_effect=Exception("SMTP error")):
            # Should not raise exception
            alerter.send(sample_alert)

    def test_email_alerter_message_content(self, sample_alert):
        """Test email message content formatting"""
        alerter = EmailAlerter(
            smtp_server="smtp.example.com",
            smtp_port=587,
            username="user@example.com",
            password="password",
            from_email="from@example.com",
            to_email="to@example.com",
        )
        
        with patch('smtplib.SMTP') as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__.return_value = mock_server
            mock_smtp.return_value.__exit__.return_value = None
            
            alerter.send(sample_alert)
            
            # Verify message was created
            call_args = mock_server.send_message.call_args
            assert call_args is not None
            msg = call_args[0][0]
            assert "HIGH" in msg["Subject"]
            assert sample_alert.title in msg["Subject"]
            assert msg["From"] == "from@example.com"
            assert msg["To"] == "to@example.com"
            # Check body contains alert information
            body = str(msg.get_payload())
            assert sample_alert.description in body


class TestSlackAlerter:
    """Test cases for SlackAlerter"""

    def test_slack_alerter_init(self):
        """Test SlackAlerter initialization"""
        alerter = SlackAlerter(webhook_url="https://hooks.slack.com/test")
        assert alerter.webhook_url == "https://hooks.slack.com/test"

    def test_slack_alerter_send_success(self, sample_alert):
        """Test successful Slack alert sending"""
        alerter = SlackAlerter(webhook_url="https://hooks.slack.com/test")
        
        with patch('httpx.post') as mock_post:
            alerter.send(sample_alert)
            
            mock_post.assert_called_once()
            call_args = mock_post.call_args
            assert call_args[0][0] == "https://hooks.slack.com/test"
            assert "json" in call_args[1]
            payload = call_args[1]["json"]
            assert "attachments" in payload
            assert payload["attachments"][0]["title"] == sample_alert.title

    def test_slack_alerter_send_error_handling(self, sample_alert):
        """Test Slack alert error handling"""
        alerter = SlackAlerter(webhook_url="https://hooks.slack.com/test")
        
        with patch('httpx.post', side_effect=Exception("Network error")):
            # Should not raise exception
            alerter.send(sample_alert)

    def test_slack_alerter_severity_colors(self, sample_alert):
        """Test Slack alert severity color mapping"""
        alerter = SlackAlerter(webhook_url="https://hooks.slack.com/test")
        
        with patch('httpx.post') as mock_post:
            # Test critical severity
            sample_alert.severity = RiskLevel.CRITICAL
            alerter.send(sample_alert)
            payload = mock_post.call_args[1]["json"]
            assert payload["attachments"][0]["color"] == "danger"
            
            # Test high severity
            sample_alert.severity = RiskLevel.HIGH
            alerter.send(sample_alert)
            payload = mock_post.call_args[1]["json"]
            assert payload["attachments"][0]["color"] == "warning"
            
            # Test low severity
            sample_alert.severity = RiskLevel.LOW
            alerter.send(sample_alert)
            payload = mock_post.call_args[1]["json"]
            assert payload["attachments"][0]["color"] == "good"

    def test_slack_alerter_with_recommended_action(self, sample_alert):
        """Test Slack alert with recommended action"""
        alerter = SlackAlerter(webhook_url="https://hooks.slack.com/test")
        sample_alert.recommended_action = "Update immediately"
        
        with patch('httpx.post') as mock_post:
            alerter.send(sample_alert)
            payload = mock_post.call_args[1]["json"]
            fields = payload["attachments"][0]["fields"]
            assert any(f["title"] == "Recommended Action" for f in fields)


class TestWebhookAlerter:
    """Test cases for WebhookAlerter"""

    def test_webhook_alerter_init(self):
        """Test WebhookAlerter initialization"""
        alerter = WebhookAlerter(webhook_url="https://example.com/webhook")
        assert alerter.webhook_url == "https://example.com/webhook"

    def test_webhook_alerter_send_success(self, sample_alert):
        """Test successful webhook alert sending"""
        alerter = WebhookAlerter(webhook_url="https://example.com/webhook")
        
        with patch('httpx.post') as mock_post:
            alerter.send(sample_alert)
            
            mock_post.assert_called_once()
            call_args = mock_post.call_args
            assert call_args[0][0] == "https://example.com/webhook"
            assert "json" in call_args[1]
            payload = call_args[1]["json"]
            assert payload["id"] == sample_alert.id
            assert payload["package"] == str(sample_alert.package)
            assert payload["alert_type"] == sample_alert.alert_type
            assert payload["severity"] == sample_alert.severity.value

    def test_webhook_alerter_send_error_handling(self, sample_alert):
        """Test webhook alert error handling"""
        alerter = WebhookAlerter(webhook_url="https://example.com/webhook")
        
        with patch('httpx.post', side_effect=Exception("Network error")):
            # Should not raise exception
            alerter.send(sample_alert)

    def test_webhook_alerter_payload_structure(self, sample_alert):
        """Test webhook alert payload structure"""
        alerter = WebhookAlerter(webhook_url="https://example.com/webhook")
        
        with patch('httpx.post') as mock_post:
            alerter.send(sample_alert)
            payload = mock_post.call_args[1]["json"]
            
            assert "id" in payload
            assert "timestamp" in payload
            assert "package" in payload
            assert "alert_type" in payload
            assert "severity" in payload
            assert "title" in payload
            assert "description" in payload
            assert "evidence" in payload
            assert "recommended_action" in payload

