"""Supply chain attack detection analyzer"""

import logging
import uuid
from datetime import datetime, timezone

from packaging.version import InvalidVersion, Version

from provchain.data.cache import Cache
from provchain.data.db import Database
from provchain.data.models import (
    AnalysisResult,
    AttackHistory,
    Finding,
    PackageMetadata,
    RiskLevel,
)
from provchain.integrations.pypi import PyPIClient
from provchain.interrogator.analyzers.base import BaseAnalyzer
from provchain.interrogator.analyzers.typosquat import TyposquatAnalyzer

logger = logging.getLogger(__name__)


class AttackAnalyzer(BaseAnalyzer):
    """Analyzer for detecting supply chain attacks"""

    name = "attack"

    def __init__(self, cache: Cache | None = None, db: Database | None = None):
        """Initialize attack analyzer

        Args:
            cache: Optional cache for API responses
            db: Optional database for storing attack history
        """
        self.cache = cache
        self.db = db
        self.typosquat_analyzer = TyposquatAnalyzer()

    def analyze(self, package_metadata: PackageMetadata) -> AnalysisResult:
        """Analyze package for supply chain attacks

        Args:
            package_metadata: Package metadata to analyze

        Returns:
            AnalysisResult with attack findings
        """
        package = package_metadata.identifier
        findings = []
        risk_score = 0.0
        attacks_detected = []

        # 1. Check for typosquatting (enhanced)
        typosquat_result = self.typosquat_analyzer.analyze(package_metadata)
        if typosquat_result.findings:
            for finding in typosquat_result.findings:
                if finding.severity in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                    findings.append(finding)
                    risk_score = max(risk_score, typosquat_result.risk_score)

                    # Record as attack history
                    attack = AttackHistory(
                        id=str(uuid.uuid4()),
                        package=package,
                        attack_type="typosquat",
                        detected_at=datetime.now(timezone.utc),
                        pattern_id=finding.id,
                        severity=finding.severity,
                        description=finding.title,
                        evidence={"finding_id": finding.id, "evidence": finding.evidence},
                        source="provchain",
                    )
                    attacks_detected.append(attack)

        # 2. Check for account takeover (maintainer changes)
        account_takeover_findings = self._detect_account_takeover(package_metadata)
        findings.extend(account_takeover_findings)
        for finding in account_takeover_findings:
            risk_score = max(risk_score, 8.0 if finding.severity == RiskLevel.HIGH else 6.0)

            attack = AttackHistory(
                id=str(uuid.uuid4()),
                package=package,
                attack_type="account_takeover",
                detected_at=datetime.now(timezone.utc),
                pattern_id="account_takeover_maintainer_change",
                severity=finding.severity,
                description=finding.title,
                evidence={"finding_id": finding.id, "evidence": finding.evidence},
                source="provchain",
            )
            attacks_detected.append(attack)

        # 3. Check for dependency confusion
        dep_confusion_findings = self._detect_dependency_confusion(package_metadata)
        findings.extend(dep_confusion_findings)
        for finding in dep_confusion_findings:
            if finding.severity == RiskLevel.CRITICAL:
                score = 9.0
            elif finding.severity == RiskLevel.HIGH:
                score = 7.5
            elif finding.severity == RiskLevel.MEDIUM:
                score = 5.5
            else:
                score = 4.0
            risk_score = max(risk_score, score)

            attack = AttackHistory(
                id=str(uuid.uuid4()),
                package=package,
                attack_type="dependency_confusion",
                detected_at=datetime.now(timezone.utc),
                pattern_id="dependency_confusion_private_name",
                severity=finding.severity,
                description=finding.title,
                evidence={"finding_id": finding.id, "evidence": finding.evidence},
                source="provchain",
            )
            attacks_detected.append(attack)

        # 4. Check for malicious updates
        malicious_update_findings = self._detect_malicious_update(package_metadata)
        findings.extend(malicious_update_findings)
        for finding in malicious_update_findings:
            risk_score = max(risk_score, 8.5 if finding.severity == RiskLevel.HIGH else 6.5)

            attack = AttackHistory(
                id=str(uuid.uuid4()),
                package=package,
                attack_type="malicious_update",
                detected_at=datetime.now(timezone.utc),
                pattern_id="malicious_update_version_jump",
                severity=finding.severity,
                description=finding.title,
                evidence={"finding_id": finding.id, "evidence": finding.evidence},
                source="provchain",
            )
            attacks_detected.append(attack)

        # 5. Check historical attack patterns
        if self.db:
            historical_attacks = self.db.get_attack_history(
                package.ecosystem, package.name, limit=10
            )
            if historical_attacks:
                for hist_attack in historical_attacks:
                    if not hist_attack.resolved:
                        findings.append(
                            Finding(
                                id=f"historical_{hist_attack.id}",
                                title=f"Historical attack detected: {hist_attack.attack_type}",
                                description=hist_attack.description,
                                severity=hist_attack.severity,
                                evidence=[
                                    f"Detected: {hist_attack.detected_at}",
                                    f"Source: {hist_attack.source}",
                                ],
                                remediation="Review historical attack patterns for this package",
                            )
                        )
                        risk_score = max(risk_score, 7.0)

        # Store attack history
        if self.db and attacks_detected:
            for attack in attacks_detected:
                try:
                    self.db.store_attack_history(attack)
                except Exception as e:
                    logger.warning("Failed to store attack history %s: %s", attack.id, e)
                    continue

        confidence = self.get_confidence(findings)

        return AnalysisResult(
            analyzer=self.name,
            risk_score=min(risk_score, 10.0),
            confidence=confidence,
            findings=findings,
            raw_data={
                "attacks_detected": len(attacks_detected),
                "attack_types": list(set(a.attack_type for a in attacks_detected)),
            },
        )

    def _detect_account_takeover(self, package_metadata: PackageMetadata) -> list[Finding]:
        """Detect account takeover attacks

        Uses prior DB snapshots when available, but also performs lightweight
        heuristic checks that work without prior state (bootstrapping).

        Args:
            package_metadata: Package metadata

        Returns:
            List of findings
        """
        findings = []
        package = package_metadata.identifier
        current_maintainers = {m.username for m in package_metadata.maintainers}

        if self.db:
            previous_snapshot = self.db.get_latest_maintainer_snapshot(
                package.ecosystem, package.name
            )

            if previous_snapshot:
                previous_maintainers = {
                    m.get("username", "") for m in previous_snapshot if m.get("username")
                }

                # Check for maintainer changes
                if current_maintainers != previous_maintainers:
                    removed = previous_maintainers - current_maintainers
                    added = current_maintainers - previous_maintainers

                    if removed or added:
                        findings.append(
                            Finding(
                                id="account_takeover_maintainer_change",
                                title="Maintainer change detected",
                                description=(
                                    f"Package maintainers changed. "
                                    f"Removed: {', '.join(removed) if removed else 'None'}. "
                                    f"Added: {', '.join(added) if added else 'None'}"
                                ),
                                severity=RiskLevel.HIGH,
                                evidence=[
                                    f"Previous maintainers: {', '.join(previous_maintainers)}",
                                    f"Current maintainers: {', '.join(current_maintainers)}",
                                ],
                                remediation="Verify maintainer changes are legitimate and authorized",
                            )
                        )
            else:
                # No prior snapshot — bootstrap by storing the current state
                logger.info(
                    "No prior maintainer snapshot for %s/%s, bootstrapping from current data",
                    package.ecosystem,
                    package.name,
                )
                try:
                    snapshot_data = [
                        {"username": m.username, "email": getattr(m, "email", None)}
                        for m in package_metadata.maintainers
                    ]
                    self.db.store_maintainer_snapshot(
                        package.ecosystem, package.name, snapshot_data
                    )
                except Exception as exc:
                    logger.warning("Failed to bootstrap maintainer snapshot: %s", exc)

        # --- Lightweight heuristic checks (work without prior state) ---

        # Check if the maintainer's account is very new relative to the package age
        if package_metadata.first_release and package_metadata.maintainers:
            now = datetime.now(timezone.utc)
            first_release = package_metadata.first_release
            if first_release.tzinfo is None:
                first_release = first_release.replace(tzinfo=timezone.utc)
            package_age_days = (now - first_release).days

            for maintainer in package_metadata.maintainers:
                account_created = getattr(maintainer, "created_at", None)
                if account_created:
                    if account_created.tzinfo is None:
                        account_created = account_created.replace(tzinfo=timezone.utc)
                    account_age_days = (now - account_created).days
                    if account_age_days < 30 and package_age_days > 365:
                        findings.append(
                            Finding(
                                id="account_takeover_new_maintainer_old_package",
                                title="New maintainer on established package",
                                description=(
                                    f"Maintainer '{maintainer.username}' account is only "
                                    f"{account_age_days} days old, but the package is "
                                    f"{package_age_days} days old."
                                ),
                                severity=RiskLevel.MEDIUM,
                                evidence=[
                                    f"Account age: {account_age_days} days",
                                    f"Package age: {package_age_days} days",
                                    f"Maintainer: {maintainer.username}",
                                ],
                                remediation=(
                                    "Verify this maintainer was intentionally added "
                                    "by the original package authors."
                                ),
                            )
                        )

        # Check if maintainer has very few packages for a popular package
        if (
            package_metadata.download_count is not None
            and package_metadata.download_count > 10_000
            and package_metadata.maintainers
        ):
            for maintainer in package_metadata.maintainers:
                other_packages = getattr(maintainer, "package_count", None)
                if other_packages is not None and other_packages <= 2:
                    findings.append(
                        Finding(
                            id="account_takeover_low_activity_maintainer",
                            title="Popular package maintained by low-activity account",
                            description=(
                                f"Maintainer '{maintainer.username}' has only "
                                f"{other_packages} package(s) but maintains a package "
                                f"with {package_metadata.download_count:,} downloads."
                            ),
                            severity=RiskLevel.MEDIUM,
                            evidence=[
                                f"Maintainer: {maintainer.username}",
                                f"Maintainer package count: {other_packages}",
                                f"Package downloads: {package_metadata.download_count}",
                            ],
                            remediation=(
                                "Verify the maintainer's identity and that this is "
                                "not a compromised or hijacked account."
                            ),
                        )
                    )

        return findings

    def _detect_dependency_confusion(self, package_metadata: PackageMetadata) -> list[Finding]:
        """Detect dependency confusion attacks

        Uses multiple indicators with graduated severity to reduce false positives.

        Args:
            package_metadata: Package metadata

        Returns:
            List of findings
        """
        findings = []
        package = package_metadata.identifier

        # Collect indicators of dependency confusion
        suspicious_indicators = []

        # 1. Low download count (default threshold: 50)
        download_threshold = 50
        if (
            package_metadata.download_count is not None
            and package_metadata.download_count < download_threshold
        ):
            suspicious_indicators.append(f"Low download count: {package_metadata.download_count}")

        # 2. Recent creation (< 30 days for HIGH+)
        if package_metadata.first_release:
            now = datetime.now(timezone.utc)
            first_release = package_metadata.first_release
            if first_release.tzinfo is None:
                first_release = first_release.replace(tzinfo=timezone.utc)
            days_since_first = (now - first_release).days
            if days_since_first < 30:
                suspicious_indicators.append(f"Very recently created: {days_since_first} days ago")

        # 3. Name suggests private/internal package
        private_name_patterns = ["internal", "private", "corp", "company", "enterprise"]
        if any(pattern in package.name.lower() for pattern in private_name_patterns):
            suspicious_indicators.append("Package name suggests private/internal package")

        # 4. No description or very short description
        description = getattr(package_metadata, "description", None) or ""
        if len(description.strip()) < 20:
            suspicious_indicators.append(
                f"Missing or very short description ({len(description.strip())} chars)"
            )

        # 5. No homepage or repository URL
        homepage = getattr(package_metadata, "homepage_url", None)
        repo_url = getattr(package_metadata, "repository_url", None)
        if not homepage and not repo_url:
            suspicious_indicators.append("No homepage or repository URL")

        # 6. Single maintainer with no other packages
        if package_metadata.maintainers and len(package_metadata.maintainers) == 1:
            maintainer = package_metadata.maintainers[0]
            other_packages = getattr(maintainer, "package_count", None)
            if other_packages is not None and other_packages <= 1:
                suspicious_indicators.append(
                    f"Single maintainer '{maintainer.username}' with no other packages"
                )

        # 7. Name contains org-specific patterns (hyphenated with common org prefixes)
        org_prefixes = [
            "mycompany-",
            "myorg-",
            "acme-",
            "ourteam-",
            "devteam-",
        ]
        name_lower = package.name.lower()
        if any(name_lower.startswith(prefix) for prefix in org_prefixes):
            suspicious_indicators.append("Package name follows org-specific naming pattern")
        # Also check for hyphenated names with "internal"/"private" as component
        name_parts = set(name_lower.replace("_", "-").split("-"))
        if name_parts & {"internal", "private", "corp", "staging", "dev"}:
            # Only add if not already caught by pattern 3
            indicator_text = "Package name component suggests internal/private usage"
            if (
                indicator_text not in suspicious_indicators
                and "Package name suggests private/internal package" not in suspicious_indicators
            ):
                suspicious_indicators.append(indicator_text)

        # --- Graduated severity based on indicator count ---
        indicator_count = len(suspicious_indicators)

        if indicator_count >= 2:
            if indicator_count >= 4:
                severity = RiskLevel.CRITICAL
                label = "Strong indicators"
            elif indicator_count >= 3:
                severity = RiskLevel.HIGH
                label = "Multiple indicators"
            else:
                severity = RiskLevel.MEDIUM
                label = "Some indicators"

            logger.info(
                "Dependency confusion check for %s: %d indicators (%s)",
                package.name,
                indicator_count,
                severity.value,
            )

            findings.append(
                Finding(
                    id="dependency_confusion_indicators",
                    title=f"Potential dependency confusion attack ({label})",
                    description=(
                        f"Package shows {indicator_count} indicators of dependency "
                        f"confusion attack: {', '.join(suspicious_indicators)}"
                    ),
                    severity=severity,
                    evidence=suspicious_indicators,
                    remediation="Verify this is not a malicious package mimicking a private package name",
                )
            )

        return findings

    def _detect_malicious_update(self, package_metadata: PackageMetadata) -> list[Finding]:
        """Detect malicious update attacks

        Flags truly suspicious version jumps while allowing normal semver progression.

        Args:
            package_metadata: Package metadata

        Returns:
            List of findings
        """
        findings: list[Finding] = []
        package = package_metadata.identifier

        try:
            # Get version history
            with PyPIClient(cache=self.cache) as pypi:
                versions = pypi.get_version_list(package.name)

                if len(versions) < 2:
                    return findings

                # Parse current version
                try:
                    current_version = Version(package.version)
                except InvalidVersion:
                    return findings

                # Check for unusual version jumps
                previous_versions = []
                for v_str in versions:
                    try:
                        v = Version(v_str)
                        if v < current_version:
                            previous_versions.append(v)
                    except InvalidVersion:
                        continue

                if previous_versions:
                    # Get the most recent previous version
                    previous_version = max(previous_versions)

                    # Calculate version jump
                    major_jump = current_version.major - previous_version.major

                    # --- Suspicious version jump checks ---
                    suspicious = False
                    evidence = [
                        f"Previous version: {previous_version}",
                        f"Current version: {current_version}",
                    ]
                    description_parts = []

                    # 1. Skipping multiple major versions (>= 3) is unusual
                    if major_jump >= 3:
                        suspicious = True
                        description_parts.append(
                            f"Major version jumped by {major_jump} "
                            f"(from {previous_version} to {current_version})"
                        )
                        evidence.append(f"Major version jump: {major_jump}")

                    # 2. Jump to an unexpectedly high version number
                    if current_version.major >= 99 and previous_version.major < 50:
                        suspicious = True
                        description_parts.append(
                            f"Version jumped to unusually high major version "
                            f"{current_version.major}"
                        )
                        evidence.append(f"High version number: {current_version.major}")

                    if suspicious:
                        findings.append(
                            Finding(
                                id="malicious_update_version_jump",
                                title="Unusual version jump detected",
                                description=(
                                    f"Version jumped from {previous_version} to "
                                    f"{current_version}. "
                                    + " ".join(description_parts)
                                    + " This may indicate a malicious update."
                                ),
                                severity=RiskLevel.MEDIUM,
                                evidence=evidence,
                                remediation="Review changelog and verify update is legitimate",
                            )
                        )

                    # 3. Release frequency anomaly: dormant package suddenly updated
                    if len(previous_versions) >= 2:
                        # Try to get release dates from PyPI
                        try:
                            metadata = pypi.get_package_metadata(package.name, package.version)
                            releases = metadata.get("releases", {})

                            # Get release date of the previous version
                            prev_release_info = releases.get(str(previous_version), [])
                            curr_release_info = releases.get(str(current_version), [])

                            if prev_release_info and curr_release_info:
                                prev_date_str = prev_release_info[0].get("upload_time_iso_8601")
                                curr_date_str = curr_release_info[0].get("upload_time_iso_8601")

                                if prev_date_str and curr_date_str:
                                    prev_date = datetime.fromisoformat(
                                        prev_date_str.replace("Z", "+00:00")
                                    )
                                    curr_date = datetime.fromisoformat(
                                        curr_date_str.replace("Z", "+00:00")
                                    )
                                    gap_days = (curr_date - prev_date).days

                                    if gap_days > 365:
                                        findings.append(
                                            Finding(
                                                id="malicious_update_dormant_release",
                                                title="Dormant package suddenly updated",
                                                description=(
                                                    f"Package had no releases for "
                                                    f"{gap_days} days (>{gap_days // 365} year(s)) "
                                                    f"before this update. This may indicate "
                                                    f"a compromised maintainer account."
                                                ),
                                                severity=RiskLevel.MEDIUM,
                                                evidence=[
                                                    f"Previous release: {previous_version} "
                                                    f"on {prev_date.date()}",
                                                    f"Current release: {current_version} "
                                                    f"on {curr_date.date()}",
                                                    f"Gap: {gap_days} days",
                                                ],
                                                remediation=(
                                                    "Verify that the update is from the "
                                                    "original maintainer and review the changelog"
                                                ),
                                            )
                                        )
                        except Exception as exc:
                            logger.debug(
                                "Could not check release frequency for %s: %s",
                                package.name,
                                exc,
                            )

        except Exception as e:
            logger.warning("Error detecting malicious update for %s: %s", package.name, e)
            # Graceful degradation - return empty findings

        return findings
