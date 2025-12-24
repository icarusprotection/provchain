"""Maintainer change monitor"""

import uuid
from datetime import timedelta

from provchain.data.db import Database
from provchain.data.models import Alert, PackageIdentifier, RiskLevel
from provchain.integrations.pypi import PyPIClient


class MaintainerMonitor:
    """Detects changes in package maintainership"""

    CHECK_INTERVAL = timedelta(hours=6)

    def __init__(self, db: Database, github_token: str | None = None):
        self.db = db
        self.github_token = github_token

    async def check(self, package_name: str) -> list[Alert]:
        """Check for maintainer changes"""
        alerts = []

        try:
            # Get current maintainers from PyPI
            with PyPIClient() as pypi:
                package_info = pypi.get_package_info(package_name)
                current_maintainers = [
                    {
                        "username": m.username,
                        "email": m.email,
                        "profile_url": m.profile_url,
                    }
                    for m in package_info.maintainers
                ]

            # Get previous snapshot
            previous_maintainers = self.db.get_latest_maintainer_snapshot("pypi", package_name)

            if previous_maintainers is not None:
                # Compare maintainers
                current_usernames = {m["username"] for m in current_maintainers}
                previous_usernames = {m["username"] for m in previous_maintainers}

                # Check for new maintainers
                new_maintainers = current_usernames - previous_usernames
                if new_maintainers:
                    alerts.append(
                        Alert(
                            id=str(uuid.uuid4()),
                            package=PackageIdentifier(
                                ecosystem="pypi", name=package_name, version=""
                            ),
                            alert_type="maintainer_added",
                            severity=RiskLevel.HIGH,
                            title=f"New maintainer(s) added to {package_name}",
                            description=f"New maintainers detected: {', '.join(new_maintainers)}",
                            evidence={"new_maintainers": list(new_maintainers)},
                            recommended_action="Verify new maintainer identity and legitimacy",
                        )
                    )

                # Check for removed maintainers
                removed_maintainers = previous_usernames - current_usernames
                if removed_maintainers:
                    alerts.append(
                        Alert(
                            id=str(uuid.uuid4()),
                            package=PackageIdentifier(
                                ecosystem="pypi", name=package_name, version=""
                            ),
                            alert_type="maintainer_removed",
                            severity=RiskLevel.MEDIUM,
                            title=f"Maintainer(s) removed from {package_name}",
                            description=f"Maintainers removed: {', '.join(removed_maintainers)}",
                            evidence={"removed_maintainers": list(removed_maintainers)},
                            recommended_action="Verify maintainer removal is legitimate",
                        )
                    )

            # Store current snapshot
            self.db.store_maintainer_snapshot("pypi", package_name, current_maintainers)

        except Exception:
            # Log error
            pass

        return alerts
