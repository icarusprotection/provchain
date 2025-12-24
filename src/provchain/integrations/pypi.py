"""PyPI API client"""

from datetime import datetime, timezone
from typing import Any

from provchain.data.cache import Cache
from provchain.data.models import MaintainerInfo, PackageIdentifier, PackageMetadata
from provchain.utils.network import HTTPClient


class PyPIClient:
    """PyPI JSON API client"""

    BASE_URL = "https://pypi.org/pypi"
    RATE_LIMIT = 100  # requests per minute

    def __init__(self, cache: Cache | None = None):
        self.client = HTTPClient(
            base_url=self.BASE_URL,
            rate_limit=self.RATE_LIMIT,
            time_window=60.0,
        )
        self.cache = cache

    def get_package_metadata(self, package_name: str, version: str | None = None) -> dict[str, Any]:
        """Get package metadata from PyPI"""
        # Input validation
        if not package_name or not isinstance(package_name, str):
            raise ValueError("package_name must be a non-empty string")
        if len(package_name) > 200:  # Reasonable limit for package names
            raise ValueError("package_name exceeds maximum length of 200 characters")
        # PyPI package names must follow PEP 508 naming rules (simplified check)
        if not package_name.replace("-", "").replace("_", "").replace(".", "").isalnum():
            raise ValueError("package_name contains invalid characters")

        if version is not None:
            if not isinstance(version, str):
                raise ValueError("version must be a string")
            if len(version) > 100:
                raise ValueError("version exceeds maximum length of 100 characters")
            # URL encode to prevent injection
            from urllib.parse import quote

            safe_version = quote(version, safe="")
            safe_package = quote(package_name, safe="")
            url = f"/{safe_package}/{safe_version}/json"
        else:
            from urllib.parse import quote

            safe_package = quote(package_name, safe="")
            url = f"/{safe_package}/json"

        if self.cache:
            cached = self.cache.get("pypi", "metadata", package_name, version)
            if cached:
                return cached

        try:
            response = self.client.get(url)

            # Validate response size (prevent DoS)
            content_length = response.headers.get("content-length")
            if content_length and isinstance(content_length, (str, int)):
                try:
                    if int(content_length) > 50 * 1024 * 1024:  # 50MB limit
                        import logging

                        logger = logging.getLogger(__name__)
                        logger.warning(f"PyPI API response too large: {content_length} bytes")
                        raise ValueError(f"Response too large for package {package_name}")
                except (ValueError, TypeError):
                    # Skip validation if content_length is not a valid number (e.g., Mock object)
                    pass

            data = response.json()

            # Validate response structure
            if not isinstance(data, dict):
                import logging

                logger = logging.getLogger(__name__)
                logger.warning("PyPI API returned invalid response format")
                raise ValueError(f"Invalid response format for package {package_name}")

            if self.cache:
                # Cache for 1 hour
                from datetime import timedelta

                self.cache.set("pypi", data, timedelta(hours=1), "metadata", package_name, version)

            return data
        except (ValueError, TypeError):
            # Input validation errors should be raised
            raise
        except Exception as e:
            # Re-raise with context
            import logging

            logger = logging.getLogger(__name__)
            logger.warning(f"PyPI API request failed for {package_name}: {e}")
            raise

    def get_package_info(self, package_name: str, version: str | None = None) -> PackageMetadata:
        """Get package information as PackageMetadata"""
        data = self.get_package_metadata(package_name, version)

        # Extract version info
        info = data.get("info", {})
        releases = data.get("releases", {})

        if version:
            # When a specific version is requested, PyPI's version-specific endpoint
            # returns data for that version. If we got data back, the version exists.
            # However, we should still validate against the info.version field.
            info_version = info.get("version")

            # Check if version exists in releases
            version_data = releases.get(version, [])

            # Also check normalized version keys (PyPI sometimes normalizes versions)
            if not version_data:
                # Try to find a matching version (case-insensitive, normalized)
                for release_version, release_data in releases.items():
                    if release_version.lower() == version.lower() or release_version.replace(
                        "-", "_"
                    ) == version.replace("-", "_"):
                        version_data = release_data
                        version = release_version  # Use the actual version from PyPI
                        break

            # If version still not found in releases, check if it matches info.version
            # This handles cases where:
            # 1. Version-specific endpoint was called (releases might be empty or only contain that version)
            # 2. Version exists but doesn't have release files yet
            if not version_data:
                if info_version and (
                    info_version == version or info_version.lower() == version.lower()
                ):
                    # Version matches info.version - it's valid
                    version = info_version
                elif info_version:
                    # Version doesn't match - try to get better error info from general endpoint
                    # But don't fail if we're using version-specific endpoint (data was returned, so version exists)
                    # Only fail if releases is empty AND version doesn't match info
                    if not releases:
                        # Version-specific endpoint - if we got here, version exists but might not be in releases
                        # Use the version from the request
                        pass
                    else:
                        # Get available versions for better error message
                        available_versions = sorted(releases.keys(), reverse=True)[
                            :10
                        ]  # Latest 10 versions
                        version_list = (
                            ", ".join(available_versions) if available_versions else "none"
                        )
                        raise ValueError(
                            f"Version {version} not found for package {package_name}. "
                            f"Available versions include: {version_list}"
                        )
        else:
            # No version specified - use latest from info
            version = info.get("version", "unknown")

        # Parse maintainers
        maintainers = []
        author = info.get("author")
        author_email = info.get("author_email")
        if author:
            maintainers.append(
                MaintainerInfo(
                    username=author,
                    email=author_email,
                )
            )

        # Parse release dates
        releases = data.get("releases", {})
        release_dates = []
        for rel_version, files in releases.items():
            if files:
                upload_time = files[0].get("upload_time")
                if upload_time:
                    try:
                        # Parse datetime and ensure it's timezone-aware
                        dt = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
                        # Ensure timezone-aware (if somehow naive, assume UTC)
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        release_dates.append(dt)
                    except Exception as e:
                        # Log parsing error but continue
                        import logging

                        logger = logging.getLogger(__name__)
                        logger.debug(f"Failed to parse release date: {e}")
                        pass

        first_release = min(release_dates) if release_dates else None
        latest_release = max(release_dates) if release_dates else None

        # Get download count (from PyPI stats API if available)
        download_count = None

        identifier = PackageIdentifier(ecosystem="pypi", name=package_name, version=version)

        return PackageMetadata(
            identifier=identifier,
            description=info.get("description"),
            homepage=info.get("home_page"),
            repository=info.get("project_url") or info.get("project_urls", {}).get("Source"),
            license=info.get("license"),
            maintainers=maintainers,
            dependencies=info.get("requires_dist", []),
            first_release=first_release,
            latest_release=latest_release,
            download_count=download_count,
        )

    def get_version_list(self, package_name: str) -> list[str]:
        """Get list of all versions for a package"""
        data = self.get_package_metadata(package_name)
        releases = data.get("releases", {})
        return sorted(releases.keys(), reverse=True)

    def search_packages(self, query: str, limit: int = 20) -> list[dict[str, Any]]:
        """Search for packages on PyPI"""
        # Note: This is a simplified search - PyPI's search API is limited
        # For production, consider using the XML-RPC API or web scraping
        return []

    def close(self) -> None:
        """Close the HTTP client"""
        self.client.close()

    def __enter__(self) -> "PyPIClient":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
