"""Attack data feeds from external sources"""

from typing import Any

from provchain.data.cache import Cache
from provchain.data.db import Database
from provchain.data.models import AttackHistory, AttackPattern, RiskLevel
from provchain.utils.network import HTTPClient


class AttackFeedFetcher:
    """Fetches attack data from external sources"""

    def __init__(self, cache: Cache | None = None, db: Database | None = None):
        """Initialize attack feed fetcher

        Args:
            cache: Optional cache for API responses
            db: Optional database for storing attack patterns and history
        """
        self.cache = cache
        self.db = db
        self.github_client = HTTPClient(
            base_url="https://api.github.com",
            rate_limit=5000,
            time_window=3600.0,
        )

    def fetch_osv_supply_chain_advisories(self) -> list[AttackHistory]:
        """Fetch supply chain attack advisories from OSV.dev

        Note: This is a future feature. OSV.dev currently doesn't provide
        a direct search API for supply chain attacks. This method is reserved
        for future implementation when such capabilities become available.

        Returns:
            List of AttackHistory records (currently returns empty list)
        """
        # Future implementation: Query OSV.dev for supply chain attack advisories
        # This would require OSV.dev to provide search/filter capabilities
        # for supply chain-specific vulnerabilities
        return []

    def fetch_github_security_advisories(self, ecosystem: str = "pypi") -> list[AttackHistory]:
        """Fetch security advisories from GitHub

        Note: This is a future feature. Full implementation would require:
        1. Access to GitHub Advisory Database API
        2. Filtering for supply chain attack patterns
        3. Parsing advisories into AttackHistory records

        Args:
            ecosystem: Package ecosystem (default: pypi)

        Returns:
            List of AttackHistory records (currently returns empty list)
        """
        # Future implementation: Query GitHub Security Advisories API
        # This would require proper authentication and API access
        return []

    def store_attack_patterns(self, patterns: list[AttackPattern]) -> None:
        """Store attack patterns in database

        Args:
            patterns: List of attack patterns to store
        """
        if not self.db:
            return

        for pattern in patterns:
            try:
                self.db.store_attack_pattern(pattern)
            except Exception as e:
                # Log error but continue processing other patterns
                import logging

                logger = logging.getLogger(__name__)
                logger.warning(f"Failed to store attack pattern {pattern.id}: {e}")
                continue

    def store_attack_history(self, attacks: list[AttackHistory]) -> None:
        """Store attack history in database

        Args:
            attacks: List of attack history records to store
        """
        if not self.db:
            return

        for attack in attacks:
            try:
                self.db.store_attack_history(attack)
            except Exception as e:
                # Log error but continue processing other attacks
                import logging

                logger = logging.getLogger(__name__)
                logger.warning(f"Failed to store attack history {attack.id}: {e}")
                continue

    def initialize_default_patterns(self) -> None:
        """Initialize default attack patterns in database"""
        if not self.db:
            return

        default_patterns = [
            AttackPattern(
                id="typosquat_levenshtein_1",
                name="Typosquatting - Levenshtein Distance 1",
                description="Package name differs from popular package by 1 character (Levenshtein distance)",
                attack_type="typosquat",
                severity=RiskLevel.HIGH,
                indicators=["levenshtein_distance=1", "similar_to_popular"],
                examples=["requests vs requets", "numpy vs numby"],
                detection_rules={"max_distance": 1, "check_popular": True},
            ),
            AttackPattern(
                id="typosquat_homoglyph",
                name="Typosquatting - Homoglyph Attack",
                description="Package uses Unicode homoglyphs to mimic popular package",
                attack_type="typosquat",
                severity=RiskLevel.CRITICAL,
                indicators=["unicode_normalization_match", "visual_similarity"],
                examples=["requests with Cyrillic 'а' instead of Latin 'a'"],
                detection_rules={"check_unicode": True, "normalize": True},
            ),
            AttackPattern(
                id="account_takeover_maintainer_change",
                name="Account Takeover - Maintainer Change",
                description="Package maintainer changed unexpectedly",
                attack_type="account_takeover",
                severity=RiskLevel.HIGH,
                indicators=["maintainer_change", "sudden_change", "no_announcement"],
                examples=[],
                detection_rules={"check_maintainer_history": True, "threshold_days": 30},
            ),
            AttackPattern(
                id="dependency_confusion_private_name",
                name="Dependency Confusion - Private Package Name",
                description="Public package with same name as private/internal package",
                attack_type="dependency_confusion",
                severity=RiskLevel.CRITICAL,
                indicators=["private_package_name", "low_downloads", "recent_creation"],
                examples=[],
                detection_rules={"check_private_names": True, "check_downloads": True},
            ),
            AttackPattern(
                id="malicious_update_version_jump",
                name="Malicious Update - Version Jump",
                description="Unusual version jump suggesting malicious update",
                attack_type="malicious_update",
                severity=RiskLevel.HIGH,
                indicators=["version_jump", "breaking_change", "suspicious_changes"],
                examples=[],
                detection_rules={"check_version_history": True, "max_jump": 2},
            ),
        ]

        self.store_attack_patterns(default_patterns)

    def close(self) -> None:
        """Close HTTP clients"""
        self.github_client.close()

    def __enter__(self) -> "AttackFeedFetcher":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
