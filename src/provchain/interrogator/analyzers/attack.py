"""Supply chain attack detection analyzer"""

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
            risk_score = max(risk_score, 9.0 if finding.severity == RiskLevel.CRITICAL else 7.0)

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
                    # Log error but continue processing
                    import logging

                    logger = logging.getLogger(__name__)
                    logger.warning(f"Failed to store attack history {attack.id}: {e}")
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

        Args:
            package_metadata: Package metadata

        Returns:
            List of findings
        """
        findings = []
        package = package_metadata.identifier

        if not self.db:
            return findings

        # Check maintainer history
        current_maintainers = {m.username for m in package_metadata.maintainers}
        previous_snapshot = self.db.get_latest_maintainer_snapshot(package.ecosystem, package.name)

        if previous_snapshot:
            previous_maintainers = {
                m.get("username", "") for m in previous_snapshot if m.get("username")
            }

            # Check for maintainer changes
            if current_maintainers != previous_maintainers:
                removed = previous_maintainers - current_maintainers
                added = current_maintainers - previous_maintainers

                if removed or added:
                    # Check if change was recent (within 30 days)
                    # This is a simplified check - in production, would check snapshot dates
                    findings.append(
                        Finding(
                            id="account_takeover_maintainer_change",
                            title="Maintainer change detected",
                            description=f"Package maintainers changed. Removed: {', '.join(removed) if removed else 'None'}. Added: {', '.join(added) if added else 'None'}",
                            severity=RiskLevel.HIGH,
                            evidence=[
                                f"Previous maintainers: {', '.join(previous_maintainers)}",
                                f"Current maintainers: {', '.join(current_maintainers)}",
                            ],
                            remediation="Verify maintainer changes are legitimate and authorized",
                        )
                    )

        return findings

    def _detect_dependency_confusion(self, package_metadata: PackageMetadata) -> list[Finding]:
        """Detect dependency confusion attacks

        Args:
            package_metadata: Package metadata

        Returns:
            List of findings
        """
        findings = []
        package = package_metadata.identifier

        # Check for indicators of dependency confusion:
        # 1. Low download count (new package)
        # 2. Recent creation
        # 3. Name suggests private/internal package

        suspicious_indicators = []

        if package_metadata.download_count is not None and package_metadata.download_count < 100:
            suspicious_indicators.append(f"Low download count: {package_metadata.download_count}")

        if package_metadata.first_release:
            # Ensure both datetimes are timezone-aware
            now = datetime.now(timezone.utc)
            first_release = package_metadata.first_release
            if first_release.tzinfo is None:
                # Naive datetime - assume UTC
                first_release = first_release.replace(tzinfo=timezone.utc)
            days_since_first = (now - first_release).days
            if days_since_first < 90:  # Less than 3 months old
                suspicious_indicators.append(f"Recently created: {days_since_first} days ago")

        # Check if name suggests private package (common patterns)
        private_name_patterns = ["internal", "private", "corp", "company", "enterprise"]
        if any(pattern in package.name.lower() for pattern in private_name_patterns):
            suspicious_indicators.append("Package name suggests private/internal package")

        if len(suspicious_indicators) >= 2:
            findings.append(
                Finding(
                    id="dependency_confusion_indicators",
                    title="Potential dependency confusion attack",
                    description=f"Package shows indicators of dependency confusion attack: {', '.join(suspicious_indicators)}",
                    severity=RiskLevel.CRITICAL,
                    evidence=suspicious_indicators,
                    remediation="Verify this is not a malicious package mimicking a private package name",
                )
            )

        return findings

    def _detect_malicious_update(self, package_metadata: PackageMetadata) -> list[Finding]:
        """Detect malicious update attacks

        Args:
            package_metadata: Package metadata

        Returns:
            List of findings
        """
        findings = []
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
                    minor_jump = current_version.minor - previous_version.minor
                    patch_jump = current_version.patch - previous_version.patch

                    # Large version jumps are suspicious
                    if major_jump > 1 or (major_jump == 1 and (minor_jump > 0 or patch_jump > 0)):
                        findings.append(
                            Finding(
                                id="malicious_update_version_jump",
                                title="Unusual version jump detected",
                                description=f"Version jumped from {previous_version} to {current_version}. This may indicate a malicious update.",
                                severity=RiskLevel.HIGH,
                                evidence=[
                                    f"Previous version: {previous_version}",
                                    f"Current version: {current_version}",
                                    f"Major jump: {major_jump}",
                                ],
                                remediation="Review changelog and verify update is legitimate",
                            )
                        )

        except Exception as e:
            # Log error for debugging but continue gracefully
            import logging

            logger = logging.getLogger(__name__)
            logger.warning(f"Error detecting malicious update for {package.name}: {e}")
            # Graceful degradation - return empty findings

        return findings
