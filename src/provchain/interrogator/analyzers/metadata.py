"""Package metadata quality analyzer"""

import re
from urllib.parse import urlparse

from provchain.data.models import AnalysisResult, Finding, PackageMetadata, RiskLevel
from provchain.interrogator.analyzers.base import BaseAnalyzer


class MetadataAnalyzer(BaseAnalyzer):
    """Analyzes package metadata for quality and suspicious patterns"""

    name = "metadata"

    OSI_APPROVED_LICENSES = [
        "MIT",
        "Apache-2.0",
        "BSD-3-Clause",
        "BSD-2-Clause",
        "GPL-3.0",
        "GPL-2.0",
        "LGPL-3.0",
        "LGPL-2.1",
        "MPL-2.0",
        "ISC",
        "Artistic-2.0",
        "Python-2.0",
        "ZPL-2.1",
        "CPOL",
        "CPAL",
        "CDDL-1.0",
        "EPL-1.0",
        "EPL-2.0",
    ]

    def is_valid_url(self, url: str) -> bool:
        """Check if URL is valid"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False

    def analyze(self, package_metadata: PackageMetadata) -> AnalysisResult:
        """Analyze package metadata"""
        findings = []
        risk_score = 0.0

        # Check description
        if not package_metadata.description or len(package_metadata.description.strip()) < 10:
            risk_score += 1.5
            findings.append(
                Finding(
                    id="metadata_no_description",
                    title="Missing or very short description",
                    description="Package lacks a meaningful description",
                    severity=RiskLevel.LOW,
                    evidence=[],
                    remediation="Package should include a clear description",
                )
            )

        # Check homepage/repository URL
        if package_metadata.homepage:
            if not self.is_valid_url(package_metadata.homepage):
                risk_score += 2.0
                findings.append(
                    Finding(
                        id="metadata_invalid_homepage",
                        title="Invalid homepage URL",
                        description=f"Homepage URL is invalid: {package_metadata.homepage}",
                        severity=RiskLevel.MEDIUM,
                        evidence=[f"Homepage: {package_metadata.homepage}"],
                    )
                )

        if package_metadata.repository:
            if not self.is_valid_url(package_metadata.repository):
                risk_score += 2.5
                findings.append(
                    Finding(
                        id="metadata_invalid_repository",
                        title="Invalid repository URL",
                        description=f"Repository URL is invalid: {package_metadata.repository}",
                        severity=RiskLevel.MEDIUM,
                        evidence=[f"Repository: {package_metadata.repository}"],
                    )
                )
        else:
            risk_score += 1.0
            findings.append(
                Finding(
                    id="metadata_no_repository",
                    title="No repository URL",
                    description="Package does not specify a source repository",
                    severity=RiskLevel.LOW,
                    evidence=[],
                )
            )

        # Check license
        if not package_metadata.license:
            risk_score += 1.5
            findings.append(
                Finding(
                    id="metadata_no_license",
                    title="No license specified",
                    description="Package does not specify a license",
                    severity=RiskLevel.MEDIUM,
                    evidence=[],
                    remediation="Package should specify a license",
                )
            )
        else:
            # Check if license is OSI-approved
            license_upper = package_metadata.license.upper()
            is_osi_approved = any(
                osi_license.upper() in license_upper for osi_license in self.OSI_APPROVED_LICENSES
            )

            if not is_osi_approved:
                risk_score += 0.5
                findings.append(
                    Finding(
                        id="metadata_non_osi_license",
                        title="Non-OSI approved license",
                        description=f"License '{package_metadata.license}' is not OSI-approved",
                        severity=RiskLevel.LOW,
                        evidence=[f"License: {package_metadata.license}"],
                    )
                )

        # Check release history
        if package_metadata.first_release and package_metadata.latest_release:
            release_span = package_metadata.latest_release - package_metadata.first_release
            if release_span.days < 7:
                # Very new package
                risk_score += 1.0
                findings.append(
                    Finding(
                        id="metadata_very_new",
                        title="Very new package",
                        description=f"Package was first released {release_span.days} days ago",
                        severity=RiskLevel.LOW,
                        evidence=[
                            f"First release: {package_metadata.first_release.isoformat()}",
                            f"Latest release: {package_metadata.latest_release.isoformat()}",
                        ],
                    )
                )

        # Check download count (if available)
        if package_metadata.download_count is not None:
            if package_metadata.download_count == 0:
                risk_score += 0.5
                findings.append(
                    Finding(
                        id="metadata_no_downloads",
                        title="No downloads",
                        description="Package has no recorded downloads",
                        severity=RiskLevel.LOW,
                        evidence=[],
                    )
                )

        confidence = self.get_confidence(findings)

        return AnalysisResult(
            analyzer=self.name,
            risk_score=min(risk_score, 10.0),
            confidence=confidence,
            findings=findings,
            raw_data={
                "has_description": bool(package_metadata.description),
                "has_homepage": bool(package_metadata.homepage),
                "has_repository": bool(package_metadata.repository),
                "has_license": bool(package_metadata.license),
            },
        )

