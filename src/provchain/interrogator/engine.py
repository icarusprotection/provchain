"""Interrogator engine: Main analysis orchestrator"""

import concurrent.futures
import logging

from provchain.data.cache import Cache
from provchain.data.db import Database
from provchain.data.models import (
    AnalysisResult,
    Finding,
    PackageIdentifier,
    PackageMetadata,
    RiskLevel,
    VetReport,
)
from provchain.integrations.pypi import PyPIClient
from provchain.interrogator.analyzers.attack import AttackAnalyzer
from provchain.interrogator.analyzers.base import BaseAnalyzer
from provchain.interrogator.analyzers.behavior import BehaviorAnalyzer
from provchain.interrogator.analyzers.install_hooks import InstallHookAnalyzer
from provchain.interrogator.analyzers.maintainer import MaintainerAnalyzer
from provchain.interrogator.analyzers.metadata import MetadataAnalyzer
from provchain.interrogator.analyzers.typosquat import TyposquatAnalyzer
from provchain.interrogator.analyzers.vulnerability import VulnerabilityAnalyzer
from provchain.interrogator.risk_scorer import RiskScorer
from provchain.interrogator.sandbox.container import check_docker_available

logger = logging.getLogger(__name__)

# Analyzers that can run without real PyPI metadata (only need the package name)
_METADATA_INDEPENDENT_ANALYZERS = {"typosquat"}


class InterrogatorEngine:
    """Main orchestrator for package analysis"""

    def __init__(
        self,
        github_token: str | None = None,
        analyzers: list[str] | None = None,
        enable_behavior: bool = False,
        cache: Cache | None = None,
        db: Database | None = None,
    ):
        self.github_token = github_token
        self.enable_behavior = enable_behavior
        self.cache = cache
        self.db = db
        self.analyzers_enabled = analyzers or [
            "typosquat",
            "maintainer",
            "metadata",
            "install_hooks",
            "vulnerability",
            "attack",
        ]
        if enable_behavior:
            self.analyzers_enabled.append("behavior")

        self.risk_scorer = RiskScorer()

    def _get_analyzers(self) -> list[BaseAnalyzer]:
        """Get list of enabled analyzers"""
        analyzers: list[BaseAnalyzer] = []

        if "typosquat" in self.analyzers_enabled:
            analyzers.append(TyposquatAnalyzer())

        if "maintainer" in self.analyzers_enabled:
            analyzers.append(MaintainerAnalyzer(github_token=self.github_token))

        if "metadata" in self.analyzers_enabled:
            analyzers.append(MetadataAnalyzer())

        if "install_hooks" in self.analyzers_enabled:
            analyzers.append(InstallHookAnalyzer())

        if "vulnerability" in self.analyzers_enabled:
            analyzers.append(VulnerabilityAnalyzer(cache=self.cache, db=self.db))

        if "attack" in self.analyzers_enabled:
            analyzers.append(AttackAnalyzer(cache=self.cache, db=self.db))

        if "behavior" in self.analyzers_enabled:
            docker_available = check_docker_available()
            analyzers.append(BehaviorAnalyzer(docker_available=docker_available))

        return analyzers

    @staticmethod
    def _minimal_metadata(identifier: PackageIdentifier) -> PackageMetadata:
        """Create a minimal PackageMetadata when PyPI metadata is unavailable."""
        return PackageMetadata(
            identifier=identifier,
            description=None,
            homepage=None,
            repository=None,
            license=None,
            maintainers=[],
            dependencies=[],
            first_release=None,
            latest_release=None,
            download_count=None,
        )

    def analyze_package(
        self, package_identifier: PackageIdentifier, package_metadata: PackageMetadata | None = None
    ) -> VetReport:
        """Analyze a package and return report"""
        metadata_fetch_failed = False

        # Fetch metadata if not provided
        if package_metadata is None:
            try:
                with PyPIClient() as pypi:
                    package_metadata = pypi.get_package_info(
                        package_identifier.name,
                        package_identifier.version
                        if package_identifier.version != "latest"
                        else None,
                    )
            except Exception as e:
                logger.warning("PyPI metadata fetch failed for %s: %s", package_identifier.name, e)
                metadata_fetch_failed = True
                package_metadata = self._minimal_metadata(package_identifier)

        # Get analyzers
        all_analyzers = self._get_analyzers()

        # If metadata fetch failed, only run metadata-independent analyzers
        if metadata_fetch_failed:
            analyzers = [a for a in all_analyzers if a.name in _METADATA_INDEPENDENT_ANALYZERS]
        else:
            analyzers = all_analyzers

        # Run analyzers in parallel
        results = []
        if analyzers:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max(len(analyzers), 1)
            ) as executor:
                futures = {
                    executor.submit(analyzer.analyze, package_metadata): analyzer
                    for analyzer in analyzers
                }

                for future in concurrent.futures.as_completed(futures):
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        analyzer = futures[future]
                        logger.warning("Analyzer %s failed: %s", analyzer.name, e)
                        results.append(
                            AnalysisResult(
                                analyzer=analyzer.name,
                                risk_score=0.0,
                                confidence=0.0,
                                findings=[],
                                raw_data={"error": str(e)},
                            )
                        )

        # If metadata fetch failed, add a finding about it
        if metadata_fetch_failed:
            results.append(
                AnalysisResult(
                    analyzer="metadata",
                    risk_score=3.0,
                    confidence=0.5,
                    findings=[
                        Finding(
                            id="package_not_found",
                            title="Package not found on PyPI",
                            description=(
                                f"Package '{package_identifier.name}' does not exist on PyPI. "
                                "This could indicate a typo, a removed package, or a package "
                                "that has not been published yet."
                            ),
                            severity=RiskLevel.MEDIUM,
                            evidence=[f"Package: {package_identifier.name}"],
                            remediation="Verify the package name is correct before installing.",
                        )
                    ],
                    raw_data={"package_exists": False},
                )
            )

        # Calculate risk score
        risk_score_data = self.risk_scorer.calculate(results)
        overall_risk = self.risk_scorer.get_risk_level(risk_score_data.total)

        # Generate recommendations
        report = VetReport(
            package=package_identifier,
            overall_risk=overall_risk,
            risk_score=risk_score_data.total,
            confidence=risk_score_data.confidence,
            results=results,
            recommendations=[],
        )

        # Add recommendations
        report.recommendations = self.risk_scorer.generate_recommendations(report)

        return report
