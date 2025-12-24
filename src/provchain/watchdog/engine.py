"""Watchdog engine: Monitoring orchestrator"""

import asyncio
from datetime import timedelta
from typing import Any

from provchain.data.db import Database
from provchain.data.models import SBOM
from provchain.watchdog.monitors.cve import CVEMonitor
from provchain.watchdog.monitors.maintainer import MaintainerMonitor
from provchain.watchdog.monitors.release import ReleaseMonitor
from provchain.watchdog.monitors.repo import RepositoryMonitor


class WatchdogEngine:
    """Main orchestrator for continuous monitoring"""

    def __init__(
        self,
        db: Database,
        github_token: str | None = None,
        check_interval_minutes: int = 60,
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

    async def check_sbom(self, sbom: SBOM) -> list[Any]:
        """Check all packages in an SBOM"""
        alerts = []

        for package in sbom.packages:
            # Run all monitors
            maintainer_alerts = await self.maintainer_monitor.check(package.name)
            alerts.extend(maintainer_alerts)

            # Get repository URL from package metadata if available
            # For now, skip repo monitoring without repo URL
            # release_alerts = await self.release_monitor.check(package.name)
            # alerts.extend(release_alerts)

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
                    # Trigger alert notifications
                    for alert in alerts:
                        # In production, this would send to configured channels
                        print(f"Alert: {alert.title} - {alert.description}")

                # Wait for next check interval
                await asyncio.sleep(self.check_interval.total_seconds())
            except Exception as e:
                # Log error and continue
                print(f"Watchdog error: {e}")
                await asyncio.sleep(60)  # Wait 1 minute before retrying

    def stop(self) -> None:
        """Stop watchdog daemon"""
        self.running = False
