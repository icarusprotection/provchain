"""Release monitor"""

import logging
import uuid
from datetime import datetime, timedelta, timezone

from packaging.version import InvalidVersion, Version

from provchain.data.db import Database
from provchain.data.models import Alert, PackageIdentifier, RiskLevel
from provchain.integrations.pypi import PyPIClient

logger = logging.getLogger(__name__)


class ReleaseMonitor:
    """Analyzes new releases for anomalies by comparing against stored version history"""

    CHECK_INTERVAL = timedelta(hours=1)

    def __init__(self, db: Database):
        self.db = db

    def _get_stored_version(self, package_name: str) -> str | None:
        """Retrieve the last known version for a package from the database."""
        session = self.db.Session()
        try:
            from provchain.data.db import ConfigRecord

            record = (
                session.query(ConfigRecord).filter_by(key=f"release_monitor:{package_name}").first()
            )
            if record:
                import json

                data = json.loads(str(record.value_json))
                result: str | None = data.get("version")
                return result
            return None
        finally:
            session.close()

    def _store_version(self, package_name: str, version: str) -> None:
        """Store the current version as the latest known version."""
        import json

        session = self.db.Session()
        try:
            from provchain.data.db import ConfigRecord

            record = (
                session.query(ConfigRecord).filter_by(key=f"release_monitor:{package_name}").first()
            )
            value = json.dumps(
                {"version": version, "updated_at": datetime.now(timezone.utc).isoformat()}
            )
            if record:
                record.value_json = value  # type: ignore[assignment]
                record.updated_at = datetime.now(timezone.utc)  # type: ignore[assignment]
            else:
                session.add(
                    ConfigRecord(
                        key=f"release_monitor:{package_name}",
                        value_json=value,
                        updated_at=datetime.now(timezone.utc),
                    )
                )
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    @staticmethod
    def _detect_version_anomalies(
        previous_version: str, current_version: str
    ) -> list[tuple[str, RiskLevel, str]]:
        """Detect anomalies between two versions.

        Returns list of (title, severity, description) tuples.
        """
        anomalies: list[tuple[str, RiskLevel, str]] = []

        try:
            prev = Version(previous_version)
            curr = Version(current_version)
        except InvalidVersion:
            return anomalies

        # Major version jump >=3 (e.g. 1.2.3 -> 5.0.0)
        if curr.major - prev.major >= 3:
            anomalies.append(
                (
                    "Suspicious major version jump",
                    RiskLevel.HIGH,
                    f"Version jumped from {previous_version} to {current_version} "
                    f"(major version increase of {curr.major - prev.major}). "
                    "Large version jumps can indicate a compromised package.",
                )
            )

        # Version number >= 99 in any component (e.g. 99.0.0)
        if curr.major >= 99 or (curr.minor is not None and curr.minor >= 99):
            anomalies.append(
                (
                    "Unusually high version number",
                    RiskLevel.HIGH,
                    f"Version {current_version} has an unusually high version number. "
                    "This pattern is associated with dependency confusion attacks.",
                )
            )

        # Version downgrade (e.g. 2.0.0 -> 1.0.0)
        if curr < prev:
            anomalies.append(
                (
                    "Version downgrade detected",
                    RiskLevel.MEDIUM,
                    f"Version went from {previous_version} to {current_version} "
                    "(downgrade). This could indicate a yanked release or hijacked package.",
                )
            )

        # Epoch change (rare and suspicious)
        if curr.epoch != prev.epoch:
            anomalies.append(
                (
                    "Version epoch changed",
                    RiskLevel.HIGH,
                    f"Version epoch changed from {prev.epoch} to {curr.epoch}. "
                    "Epoch changes are extremely rare and may indicate package manipulation.",
                )
            )

        return anomalies

    async def check(self, package_name: str) -> list[Alert]:
        """Check for new releases and detect version anomalies"""
        alerts: list[Alert] = []

        try:
            with PyPIClient() as pypi:
                package_info = pypi.get_package_info(package_name)
                current_version = package_info.identifier.version

                # Get stored version for comparison
                stored_version = self._get_stored_version(package_name)

                if stored_version is None:
                    # First time seeing this package — bootstrap by storing current version
                    logger.info(
                        "Bootstrapping release monitor for %s at version %s",
                        package_name,
                        current_version,
                    )
                    self._store_version(package_name, current_version)
                    return alerts

                if current_version == stored_version:
                    # No new release
                    return alerts

                # New version detected — run anomaly checks
                logger.info(
                    "New release for %s: %s -> %s",
                    package_name,
                    stored_version,
                    current_version,
                )

                # Always alert on new release (informational)
                alerts.append(
                    Alert(
                        id=str(uuid.uuid4()),
                        package=PackageIdentifier(
                            ecosystem="pypi", name=package_name, version=current_version
                        ),
                        alert_type="new_release",
                        severity=RiskLevel.LOW,
                        title=f"New release detected: {package_name} {current_version}",
                        description=(
                            f"Package {package_name} released version {current_version} "
                            f"(previously {stored_version})"
                        ),
                        evidence={
                            "previous_version": stored_version,
                            "current_version": current_version,
                        },
                        recommended_action="Review release notes and changes",
                    )
                )

                # Check for version anomalies
                anomalies = self._detect_version_anomalies(stored_version, current_version)
                for title, severity, description in anomalies:
                    alerts.append(
                        Alert(
                            id=str(uuid.uuid4()),
                            package=PackageIdentifier(
                                ecosystem="pypi", name=package_name, version=current_version
                            ),
                            alert_type="version_anomaly",
                            severity=severity,
                            title=f"{title}: {package_name}",
                            description=description,
                            evidence={
                                "previous_version": stored_version,
                                "current_version": current_version,
                            },
                            recommended_action=(
                                "Investigate the version change. Check package changelog, "
                                "maintainer activity, and diff the release artifacts."
                            ),
                        )
                    )

                # Update stored version
                self._store_version(package_name, current_version)

        except Exception:
            logger.error("Release check failed for package '%s'", package_name, exc_info=True)

        return alerts
