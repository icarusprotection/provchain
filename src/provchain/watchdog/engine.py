"""Watchdog engine: Monitoring orchestrator"""

import asyncio
import logging
from datetime import timedelta
from typing import Any

from provchain.data.db import Database
from provchain.data.models import SBOM, Alert
from provchain.watchdog.alerts.email import EmailAlerter
from provchain.watchdog.alerts.slack import SlackAlerter
from provchain.watchdog.alerts.webhook import WebhookAlerter
from provchain.watchdog.monitors.cve import CVEMonitor
from provchain.watchdog.monitors.maintainer import MaintainerMonitor
from provchain.watchdog.monitors.release import ReleaseMonitor
from provchain.watchdog.monitors.repo import RepositoryMonitor

logger = logging.getLogger(__name__)


class WatchdogEngine:
    """Main orchestrator for continuous monitoring"""

    def __init__(
        self,
        db: Database,
        github_token: str | None = None,
        check_interval_minutes: int = 60,
        slack_webhook_url: str | None = None,
        webhook_url: str | None = None,
        email_config: dict[str, Any] | None = None,
    ):
        self.db = db
        self.github_token = github_token
        self.check_interval = timedelta(minutes=check_interval_minutes)
        self.running = False

        # Initialize monitors
        self.maintainer_monitor = MaintainerMonitor(db, github_token)
        self.repo_monitor = RepositoryMonitor(db, github_token)
        self.release_monitor = ReleaseMonitor(db)
        self.cve_monitor = CVEMonitor(db)

        # Initialize alert channels
        self.alerters: list[Any] = []

        if slack_webhook_url:
            self.alerters.append(SlackAlerter(slack_webhook_url))
            logger.info("Slack alert channel configured")

        if webhook_url:
            self.alerters.append(WebhookAlerter(webhook_url))
            logger.info("Webhook alert channel configured")

        if email_config:
            self.alerters.append(
                EmailAlerter(
                    smtp_server=email_config["smtp_server"],
                    smtp_port=email_config["smtp_port"],
                    username=email_config["username"],
                    password=email_config["password"],
                    from_email=email_config["from_email"],
                    to_email=email_config["to_email"],
                )
            )
            logger.info("Email alert channel configured")

    async def check_sbom(self, sbom: SBOM) -> list[Any]:
        """Check all packages in an SBOM"""
        alerts = []

        for package in sbom.packages:
            # Run all monitors
            maintainer_alerts = await self.maintainer_monitor.check(package.name)
            alerts.extend(maintainer_alerts)

            # Check for release anomalies
            release_alerts = await self.release_monitor.check(package.name)
            alerts.extend(release_alerts)

        # CVE monitoring for all packages
        cve_alerts = await self.cve_monitor.check(sbom)
        alerts.extend(cve_alerts)

        # Store alerts
        for alert in alerts:
            self.db.store_alert(alert)

        return alerts

    async def run_daemon(self, sbom: SBOM) -> None:
        """Run watchdog daemon"""
        self.running = True

        while self.running:
            try:
                alerts = await self.check_sbom(sbom)
                if alerts:
                    # Dispatch alert notifications through configured channels
                    for alert in alerts:
                        logger.warning("Alert: %s - %s", alert.title, alert.description)
                        self._dispatch_alert(alert)

                # Wait for next check interval
                await asyncio.sleep(self.check_interval.total_seconds())
            except Exception:
                logger.error("Watchdog error during monitoring cycle", exc_info=True)
                await asyncio.sleep(60)  # Wait 1 minute before retrying

    def _dispatch_alert(self, alert: Alert) -> None:
        """Send an alert through all configured channels.

        Per-channel errors are logged but do not stop dispatch to other channels.
        """
        for alerter in self.alerters:
            try:
                alerter.send(alert)
            except Exception:
                logger.error(
                    "Failed to dispatch alert via %s",
                    type(alerter).__name__,
                    exc_info=True,
                )

    def stop(self) -> None:
        """Stop watchdog daemon"""
        self.running = False
