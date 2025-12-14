"""Release monitor"""

import uuid
from datetime import datetime, timedelta, timezone

from provchain.data.db import Database
from provchain.data.models import Alert, PackageIdentifier, RiskLevel
from provchain.integrations.pypi import PyPIClient


class ReleaseMonitor:
    """Analyzes new releases for anomalies"""

    CHECK_INTERVAL = timedelta(hours=1)

    def __init__(self, db: Database):
        self.db = db

    async def check(self, package_name: str) -> list[Alert]:
        """Check for new releases"""
        alerts = []

        try:
            with PyPIClient() as pypi:
                package_info = pypi.get_package_info(package_name)
                latest_version = package_info.identifier.version

                # Check if this is a new release
                # In production, would compare against stored latest version
                # For MVP, just check for unexpected version bumps
                if package_info.latest_release:
                    # Check if release is very recent (within last hour)
                    time_since_release = (
                        datetime.now(timezone.utc) - package_info.latest_release
                    ).total_seconds()
                    if time_since_release < 3600:  # Within last hour
                        alerts.append(
                            Alert(
                                id=str(uuid.uuid4()),
                                package=PackageIdentifier(
                                    ecosystem="pypi", name=package_name, version=latest_version
                                ),
                                alert_type="new_release",
                                severity=RiskLevel.LOW,
                                title=f"New release detected: {package_name} {latest_version}",
                                description=f"Package {package_name} released version {latest_version}",
                                evidence={"version": latest_version, "release_time": package_info.latest_release.isoformat()},
                                recommended_action="Review release notes and changes",
                            )
                        )

        except Exception:
            # Release check failed, skip
            pass

        return alerts

