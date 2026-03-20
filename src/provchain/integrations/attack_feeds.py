"""Attack data feeds from external sources"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from provchain.data.cache import Cache
from provchain.data.db import Database
from provchain.data.models import AttackHistory, AttackPattern, PackageIdentifier, RiskLevel
from provchain.utils.network import HTTPClient

logger = logging.getLogger(__name__)


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
        self.osv_client = HTTPClient(
            base_url="https://api.osv.dev",
            rate_limit=1000,
            time_window=60.0,
        )

    def fetch_osv_supply_chain_advisories(self) -> list[AttackHistory]:
        """Fetch supply chain attack advisories from OSV.dev

        Queries the OSV.dev batch endpoint for PyPI vulnerabilities with
        supply-chain-related keywords in their summaries/details (e.g.
        malicious, typosquat, backdoor, dependency confusion).

        Returns:
            List of AttackHistory records for known supply chain attacks
        """
        attacks: list[AttackHistory] = []

        if self.cache:
            cached = self.cache.get("attack_feeds", "osv_supply_chain")
            if cached:
                return [AttackHistory(**a) for a in cached]

        # OSV.dev supports querying all PyPI vulnerabilities via the
        # /v1/query endpoint.  We look for advisories whose IDs start
        # with MAL- (the "malicious packages" namespace) or PYSEC-.
        supply_chain_prefixes = ["MAL-", "PYSEC-"]
        supply_chain_keywords = [
            "malicious",
            "typosquat",
            "backdoor",
            "dependency confusion",
            "supply chain",
            "trojan",
            "exfiltration",
        ]

        try:
            # Query for recent PyPI vulnerabilities
            response = self.osv_client.post(
                "/v1/query",
                json={
                    "package": {"ecosystem": "PyPI", "name": ""},
                    "version": "",
                },
            )
            vulns = response.json().get("vulns", [])

            for vuln in vulns[:500]:  # Limit to avoid excessive processing
                vuln_id = vuln.get("id", "")
                summary = vuln.get("summary", "").lower()
                details = vuln.get("details", "").lower()
                combined_text = summary + " " + details

                # Check if this is a supply chain attack advisory
                is_supply_chain = any(vuln_id.startswith(p) for p in supply_chain_prefixes) or any(
                    kw in combined_text for kw in supply_chain_keywords
                )

                if not is_supply_chain:
                    continue

                # Determine attack type from content
                attack_type = "malicious_package"
                if "typosquat" in combined_text:
                    attack_type = "typosquat"
                elif "dependency confusion" in combined_text:
                    attack_type = "dependency_confusion"
                elif "backdoor" in combined_text:
                    attack_type = "backdoor"
                elif "account" in combined_text and "takeover" in combined_text:
                    attack_type = "account_takeover"

                # Extract affected package name from the advisory
                affected = vuln.get("affected", [])
                package_name = ""
                package_version = ""
                for aff in affected:
                    pkg = aff.get("package", {})
                    if pkg.get("ecosystem", "").lower() == "pypi":
                        package_name = pkg.get("name", "")
                        versions = aff.get("versions", [])
                        if versions:
                            package_version = versions[0]
                        break

                if not package_name:
                    continue

                # Parse published date
                published = vuln.get("published", "")
                try:
                    detected_at = datetime.fromisoformat(published.replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    detected_at = datetime.now(timezone.utc)

                severity = RiskLevel.HIGH
                if vuln_id.startswith("MAL-"):
                    severity = RiskLevel.CRITICAL

                attacks.append(
                    AttackHistory(
                        id=vuln_id,
                        package=PackageIdentifier(
                            ecosystem="pypi",
                            name=package_name,
                            version=package_version,
                        ),
                        attack_type=attack_type,
                        detected_at=detected_at,
                        severity=severity,
                        description=vuln.get("summary", "No summary available"),
                        evidence={"osv_id": vuln_id, "source": "osv.dev"},
                        source="osv.dev",
                    )
                )

        except Exception as e:
            logger.warning("Failed to fetch OSV supply chain advisories: %s", e)

        if self.cache and attacks:
            self.cache.set(
                "attack_feeds",
                [a.model_dump(mode="json") for a in attacks],
                timedelta(hours=6),
                "osv_supply_chain",
            )

        return attacks

    def fetch_github_security_advisories(self, ecosystem: str = "pypi") -> list[AttackHistory]:
        """Fetch security advisories from GitHub Advisory Database

        Uses the GitHub Advisory Database REST API to query for
        supply-chain-related advisories in the specified ecosystem.

        Args:
            ecosystem: Package ecosystem (default: pypi)

        Returns:
            List of AttackHistory records from GitHub advisories
        """
        attacks: list[AttackHistory] = []

        cache_key = f"github_advisories_{ecosystem}"
        if self.cache:
            cached = self.cache.get("attack_feeds", cache_key)
            if cached:
                return [AttackHistory(**a) for a in cached]

        # GitHub Advisory Database REST API endpoint
        # This is the public, unauthenticated endpoint
        try:
            response = self.github_client.get(
                "/advisories",
                params={
                    "ecosystem": ecosystem,
                    "type": "malware",
                    "per_page": 100,
                    "sort": "published",
                    "direction": "desc",
                },
            )
            advisories = response.json()

            if not isinstance(advisories, list):
                logger.warning("GitHub advisories API returned unexpected format")
                return attacks

            for advisory in advisories:
                ghsa_id = advisory.get("ghsa_id", "")
                summary = advisory.get("summary", "")
                description = advisory.get("description", "")
                severity_label = advisory.get("severity", "medium").lower()

                # Map GitHub severity to RiskLevel
                severity_map = {
                    "low": RiskLevel.LOW,
                    "medium": RiskLevel.MEDIUM,
                    "high": RiskLevel.HIGH,
                    "critical": RiskLevel.CRITICAL,
                }
                severity = severity_map.get(severity_label, RiskLevel.MEDIUM)

                # Determine attack type from content
                combined = (summary + " " + description).lower()
                attack_type = "malicious_package"
                if "typosquat" in combined:
                    attack_type = "typosquat"
                elif "dependency confusion" in combined:
                    attack_type = "dependency_confusion"

                # Extract affected packages
                vulnerabilities = advisory.get("vulnerabilities", [])
                for vuln_entry in vulnerabilities:
                    pkg = vuln_entry.get("package", {})
                    pkg_ecosystem = pkg.get("ecosystem", "").lower()
                    if pkg_ecosystem != ecosystem.lower():
                        continue

                    package_name = pkg.get("name", "")
                    if not package_name:
                        continue

                    # Parse version range
                    first_patched = vuln_entry.get("first_patched_version", {})
                    package_version = first_patched.get("identifier", "") if first_patched else ""

                    # Parse published date
                    published = advisory.get("published_at", "")
                    try:
                        detected_at = datetime.fromisoformat(published.replace("Z", "+00:00"))
                    except (ValueError, AttributeError):
                        detected_at = datetime.now(timezone.utc)

                    attacks.append(
                        AttackHistory(
                            id=ghsa_id,
                            package=PackageIdentifier(
                                ecosystem=ecosystem,
                                name=package_name,
                                version=package_version,
                            ),
                            attack_type=attack_type,
                            detected_at=detected_at,
                            severity=severity,
                            description=summary or "No summary available",
                            evidence={
                                "ghsa_id": ghsa_id,
                                "source": "github",
                                "cve_id": advisory.get("cve_id", ""),
                            },
                            source="github",
                        )
                    )

        except Exception as e:
            logger.warning("Failed to fetch GitHub security advisories: %s", e)

        if self.cache and attacks:
            self.cache.set(
                "attack_feeds",
                [a.model_dump(mode="json") for a in attacks],
                timedelta(hours=6),
                cache_key,
            )

        return attacks

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
                logger.warning("Failed to store attack pattern %s: %s", pattern.id, e)
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
                logger.warning("Failed to store attack history %s: %s", attack.id, e)
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
        self.osv_client.close()

    def __enter__(self) -> "AttackFeedFetcher":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
