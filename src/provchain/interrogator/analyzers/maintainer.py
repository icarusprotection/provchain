"""Maintainer trust analyzer"""

from datetime import datetime, timedelta, timezone

from provchain.data.models import AnalysisResult, Finding, MaintainerInfo, PackageMetadata, RiskLevel
from provchain.integrations.github import GitHubClient
from provchain.interrogator.analyzers.base import BaseAnalyzer


class MaintainerAnalyzer(BaseAnalyzer):
    """Evaluates maintainer trustworthiness signals"""

    name = "maintainer"

    def __init__(self, github_token: str | None = None):
        self.github_token = github_token

    def analyze(self, package_metadata: PackageMetadata) -> AnalysisResult:
        """Analyze maintainer trust signals"""
        findings = []
        risk_score = 0.0

        if not package_metadata.maintainers:
            risk_score += 2.0
            findings.append(
                Finding(
                    id="maintainer_missing",
                    title="No maintainer information",
                    description="Package metadata does not include maintainer information",
                    severity=RiskLevel.MEDIUM,
                    evidence=[],
                    remediation="Verify package source and legitimacy",
                )
            )

        for maintainer in package_metadata.maintainers:
            # Check account age (if available)
            if maintainer.account_created:
                account_age = datetime.now(timezone.utc) - maintainer.account_created
                if account_age < timedelta(days=90):
                    risk_score += 3.0
                    findings.append(
                        Finding(
                            id="maintainer_new_account",
                            title=f"New maintainer account: {maintainer.username}",
                            description=f"Maintainer account was created {account_age.days} days ago",
                            severity=RiskLevel.HIGH,
                            evidence=[f"Account created: {maintainer.account_created.isoformat()}"],
                            remediation="Verify maintainer identity and package legitimacy",
                        )
                    )
                elif account_age < timedelta(days=365):
                    risk_score += 1.0
                    findings.append(
                        Finding(
                            id="maintainer_young_account",
                            title=f"Young maintainer account: {maintainer.username}",
                            description=f"Maintainer account is less than 1 year old",
                            severity=RiskLevel.LOW,
                            evidence=[f"Account created: {maintainer.account_created.isoformat()}"],
                        )
                    )

            # Check package count
            if maintainer.package_count is not None:
                if maintainer.package_count == 0:
                    risk_score += 1.5
                    findings.append(
                        Finding(
                            id="maintainer_no_packages",
                            title=f"Maintainer has no other packages: {maintainer.username}",
                            description="This is the maintainer's only package on PyPI",
                            severity=RiskLevel.LOW,
                            evidence=[],
                        )
                    )
                elif maintainer.package_count > 50:
                    # Many packages could indicate automation or account compromise
                    risk_score += 0.5
                    findings.append(
                        Finding(
                            id="maintainer_many_packages",
                            title=f"Maintainer has many packages: {maintainer.username}",
                            description=f"Maintainer manages {maintainer.package_count} packages",
                            severity=RiskLevel.LOW,
                            evidence=[f"Package count: {maintainer.package_count}"],
                        )
                    )

            # Check GitHub profile if available
            if maintainer.profile_url and "github.com" in maintainer.profile_url:
                try:
                    github = GitHubClient(token=self.github_token)
                    # Extract username from URL
                    username = maintainer.profile_url.split("/")[-1]
                    user_data = github.get_user(username)

                    # Check account age
                    created_at = datetime.fromisoformat(user_data["created_at"].replace("Z", "+00:00"))
                    account_age = datetime.now(timezone.utc) - created_at
                    if account_age < timedelta(days=90):
                        risk_score += 2.0
                        findings.append(
                            Finding(
                                id="maintainer_new_github",
                                title=f"New GitHub account: {username}",
                                description=f"GitHub account was created {account_age.days} days ago",
                                severity=RiskLevel.MEDIUM,
                                evidence=[f"GitHub: {maintainer.profile_url}"],
                            )
                        )

                    # Check followers (very low could be suspicious)
                    followers = user_data.get("followers", 0)
                    if followers == 0 and account_age > timedelta(days=365):
                        risk_score += 1.0
                        findings.append(
                            Finding(
                                id="maintainer_no_followers",
                                title=f"GitHub account has no followers: {username}",
                                description="Established account with no followers may indicate inactivity or fake account",
                                severity=RiskLevel.LOW,
                                evidence=[f"GitHub: {maintainer.profile_url}"],
                            )
                        )

                    github.close()
                except Exception:
                    # GitHub API call failed, skip GitHub analysis
                    pass

            # Check email domain
            if maintainer.email:
                domain = maintainer.email.split("@")[-1] if "@" in maintainer.email else None
                if domain:
                    # Check for suspicious domains (basic check)
                    suspicious_domains = ["tempmail.com", "10minutemail.com", "guerrillamail.com"]
                    if any(sus in domain.lower() for sus in suspicious_domains):
                        risk_score += 3.0
                        findings.append(
                            Finding(
                                id="maintainer_suspicious_email",
                                title=f"Suspicious email domain: {domain}",
                                description=f"Maintainer uses temporary email service: {domain}",
                                severity=RiskLevel.HIGH,
                                evidence=[f"Email: {maintainer.email}"],
                                remediation="Verify maintainer identity",
                            )
                        )

        confidence = self.get_confidence(findings)

        return AnalysisResult(
            analyzer=self.name,
            risk_score=min(risk_score, 10.0),
            confidence=confidence,
            findings=findings,
            raw_data={"maintainer_count": len(package_metadata.maintainers)},
        )

