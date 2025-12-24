"""OSV.dev API client for vulnerability data"""

from datetime import datetime, timedelta
from typing import Any

from provchain.data.cache import Cache
from provchain.data.models import PackageIdentifier, RiskLevel, Vulnerability
from provchain.utils.network import HTTPClient


class OSVClient:
    """OSV.dev API client for querying vulnerabilities"""

    BASE_URL = "https://api.osv.dev"
    RATE_LIMIT = 1000  # OSV.dev has generous rate limits
    TIME_WINDOW = 60.0  # 1 minute

    def __init__(self, cache: Cache | None = None):
        self.client = HTTPClient(
            base_url=self.BASE_URL,
            rate_limit=self.RATE_LIMIT,
            time_window=self.TIME_WINDOW,
        )
        self.cache = cache

    def query_by_package(
        self, package_name: str, version: str | None = None, ecosystem: str = "PyPI"
    ) -> list[dict[str, Any]]:
        """Query vulnerabilities by package name and version

        Args:
            package_name: Name of the package
            version: Specific version (optional, queries all if not provided)
            ecosystem: Package ecosystem (default: PyPI)

        Returns:
            List of vulnerability objects from OSV.dev
        """
        # Input validation
        if not package_name or not isinstance(package_name, str):
            raise ValueError("package_name must be a non-empty string")
        if len(package_name) > 200:  # Reasonable limit for package names
            raise ValueError("package_name exceeds maximum length of 200 characters")
        if version is not None and (not isinstance(version, str) or len(version) > 100):
            raise ValueError("version must be a string with maximum length of 100 characters")
        if not isinstance(ecosystem, str) or len(ecosystem) > 50:
            raise ValueError("ecosystem must be a string with maximum length of 50 characters")

        if self.cache:
            cached = self.cache.get("osv", "vulnerabilities", ecosystem, package_name, version)
            if cached:
                return cached

        query = {
            "package": {
                "name": package_name,
                "ecosystem": ecosystem,
            }
        }

        if version:
            query["version"] = version

        try:
            response = self.client.post("/v1/query", json=query)

            # Validate response size (prevent DoS)
            content_length = response.headers.get("content-length")
            if content_length and isinstance(content_length, (str, int)):
                try:
                    if int(content_length) > 10 * 1024 * 1024:  # 10MB limit
                        import logging

                        logger = logging.getLogger(__name__)
                        logger.warning(f"OSV API response too large: {content_length} bytes")
                        return []
                except (ValueError, TypeError):
                    # Skip validation if content_length is not a valid number (e.g., Mock object)
                    pass

            data = response.json()

            # Validate response structure
            if not isinstance(data, dict):
                import logging

                logger = logging.getLogger(__name__)
                logger.warning("OSV API returned invalid response format")
                return []

            vulnerabilities = data.get("vulns", [])

            # Limit number of vulnerabilities returned (prevent memory issues)
            if isinstance(vulnerabilities, list) and len(vulnerabilities) > 1000:
                import logging

                logger = logging.getLogger(__name__)
                logger.warning(
                    f"OSV API returned {len(vulnerabilities)} vulnerabilities, limiting to 1000"
                )
                vulnerabilities = vulnerabilities[:1000]

            if self.cache:
                # Cache for 6 hours
                self.cache.set(
                    "osv",
                    vulnerabilities,
                    timedelta(hours=6),
                    "vulnerabilities",
                    ecosystem,
                    package_name,
                    version,
                )

            return vulnerabilities
        except (ValueError, TypeError):
            # Input validation errors should be raised
            raise
        except Exception as e:
            # Log error for debugging
            import logging

            logger = logging.getLogger(__name__)
            logger.warning(f"OSV API query failed for {package_name}: {e}")
            # Graceful degradation - return empty list if API fails
            return []

    def query_by_cve(self, cve_id: str) -> dict[str, Any] | None:
        """Query vulnerability by CVE ID

        Args:
            cve_id: CVE identifier (e.g., 'CVE-2021-44228')

        Returns:
            Vulnerability object or None if not found
        """
        # Input validation
        if not cve_id or not isinstance(cve_id, str):
            raise ValueError("cve_id must be a non-empty string")
        if len(cve_id) > 50:  # CVE IDs are typically much shorter
            raise ValueError("cve_id exceeds maximum length of 50 characters")
        # Basic format validation (CVE-YYYY-NNNNNN or GHSA-XXXX-XXXX-XXXX)
        if not (
            cve_id.startswith("CVE-") or cve_id.startswith("GHSA-") or cve_id.startswith("PYSEC-")
        ):
            import logging

            logger = logging.getLogger(__name__)
            logger.warning(f"Unusual CVE ID format: {cve_id}")

        if self.cache:
            cached = self.cache.get("osv", "cve", cve_id)
            if cached:
                return cached

        try:
            # URL encode the CVE ID to prevent injection
            from urllib.parse import quote

            safe_cve_id = quote(cve_id, safe="")
            response = self.client.get(f"/v1/vulns/{safe_cve_id}")

            # Validate response size
            content_length = response.headers.get("content-length")
            if content_length and isinstance(content_length, (str, int)):
                try:
                    if int(content_length) > 5 * 1024 * 1024:  # 5MB limit
                        import logging

                        logger = logging.getLogger(__name__)
                        logger.warning(f"OSV API response too large: {content_length} bytes")
                except (ValueError, TypeError):
                    # Skip validation if content_length is not a valid number (e.g., Mock object)
                    pass
                return None

            data = response.json()

            # Validate response structure
            if not isinstance(data, dict):
                import logging

                logger = logging.getLogger(__name__)
                logger.warning("OSV API returned invalid response format")
                return None

            if self.cache:
                self.cache.set("osv", data, timedelta(hours=24), "cve", cve_id)

            return data
        except (ValueError, TypeError):
            # Input validation errors should be raised
            raise
        except Exception as e:
            # Log error for debugging
            import logging

            logger = logging.getLogger(__name__)
            logger.warning(f"OSV API query failed for CVE {cve_id}: {e}")
            return None

    def query_by_commit(self, commit_hash: str) -> list[dict[str, Any]]:
        """Query vulnerabilities by commit hash

        Args:
            commit_hash: Git commit hash

        Returns:
            List of vulnerability objects
        """
        if self.cache:
            cached = self.cache.get("osv", "commit", commit_hash)
            if cached:
                return cached

        query = {"commit": commit_hash}

        try:
            response = self.client.post("/v1/query", json=query)
            data = response.json()

            vulnerabilities = data.get("vulns", [])

            if self.cache:
                self.cache.set("osv", vulnerabilities, timedelta(hours=24), "commit", commit_hash)

            return vulnerabilities
        except Exception:
            return []

    def parse_vulnerability(
        self, vuln_data: dict[str, Any], package: PackageIdentifier
    ) -> Vulnerability:
        """Parse OSV.dev vulnerability data into Vulnerability model

        Args:
            vuln_data: Raw vulnerability data from OSV.dev
            package: Package identifier

        Returns:
            Vulnerability model instance
        """
        vuln_id = vuln_data.get("id", "UNKNOWN")
        summary = vuln_data.get("summary", "No summary available")
        details = vuln_data.get("details", "")

        # Parse affected versions
        affected_versions = []
        fixed_versions = []
        for affected in vuln_data.get("affected", []):
            if affected.get("package", {}).get("name") == package.name:
                for version_range in affected.get("ranges", []):
                    for event in version_range.get("events", []):
                        if "fixed" in event:
                            fixed_versions.append(event["fixed"])
                        if "introduced" in event:
                            affected_versions.append(f"{event['introduced']}+")

        # Parse dates
        published = None
        modified = None
        if "published" in vuln_data:
            try:
                published = datetime.fromisoformat(vuln_data["published"].replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                pass
        if "modified" in vuln_data:
            try:
                modified = datetime.fromisoformat(vuln_data["modified"].replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                pass

        # Extract references
        references = vuln_data.get("references", [])

        # Check for CVSS score
        cvss_score = None
        severity = RiskLevel.MEDIUM

        # Check database field
        database = "osv"
        if vuln_id.startswith("CVE-"):
            database = "nvd"

        # Determine severity from database or default to medium
        # OSV doesn't always provide CVSS, so we'll calculate it later if needed

        # Check for exploit and patch availability
        exploit_available = False
        patch_available = len(fixed_versions) > 0

        # Check references for exploit indicators
        for ref in references:
            ref_url = ref.get("url", "").lower()
            if any(keyword in ref_url for keyword in ["exploit", "poc", "proof-of-concept"]):
                exploit_available = True
                break

        return Vulnerability(
            id=vuln_id,
            summary=summary,
            details=details,
            severity=severity,  # Will be updated by CVSS scorer
            cvss_score=cvss_score,
            affected_versions=affected_versions,
            fixed_versions=fixed_versions,
            published=published,
            modified=modified,
            references=[ref.get("url", "") for ref in references if "url" in ref],
            database=database,
            exploit_available=exploit_available,
            patch_available=patch_available,
        )

    def get_vulnerabilities_for_package(self, package: PackageIdentifier) -> list[Vulnerability]:
        """Get all vulnerabilities for a package

        Args:
            package: Package identifier

        Returns:
            List of Vulnerability objects
        """
        vuln_data_list = self.query_by_package(package.name, package.version, package.ecosystem)

        vulnerabilities = []
        for vuln_data in vuln_data_list:
            try:
                vuln = self.parse_vulnerability(vuln_data, package)
                vulnerabilities.append(vuln)
            except Exception as e:
                # Log error but continue processing other vulnerabilities
                import logging

                logger = logging.getLogger(__name__)
                logger.warning(f"Failed to parse vulnerability: {e}")
                continue

        return vulnerabilities

    def close(self) -> None:
        """Close the HTTP client"""
        self.client.close()

    def __enter__(self) -> "OSVClient":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
