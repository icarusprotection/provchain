"""Hash verification"""

import re
from pathlib import Path
from typing import Any

from provchain.integrations.pypi import PyPIClient
from provchain.utils.hashing import calculate_hash

# PEP 427 wheel filename: {distribution}-{version}(-{build})?-{python}-{abi}-{platform}.whl
# The version is the first component that starts with a digit.
_WHEEL_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._]*[A-Za-z0-9])?)"
    r"-(?P<version>\d[A-Za-z0-9._]*)"
    r"(?:-\d[A-Za-z0-9._]*)?"  # optional build tag
    r"-[A-Za-z0-9._]+-[A-Za-z0-9._]+-[A-Za-z0-9._]+\.whl$"
)

# sdist filename: {name}-{version}.tar.gz  or  {name}-{version}.zip
_SDIST_RE = re.compile(r"^(?P<name>.+)-(?P<version>\d[A-Za-z0-9._]*)\.(?:tar\.gz|zip)$")

# Fallback: simple {name}-{version}.whl when the full PEP 427 pattern doesn't match
# (e.g. filenames without python/abi/platform tags)
_SIMPLE_WHL_RE = re.compile(r"^(?P<name>.+)-(?P<version>\d[A-Za-z0-9._]*)\.whl$")


def _parse_artifact_filename(filename: str) -> tuple[str, str] | None:
    """Parse package name and version from a PyPI artifact filename.

    Handles wheels (PEP 427) and sdists.  Returns (name, version) or None.
    """
    m = _WHEEL_RE.match(filename)
    if m:
        # Wheel names use underscores; normalise back to hyphens for PyPI lookup
        name = m.group("name").replace("_", "-")
        return name, m.group("version")

    m = _SDIST_RE.match(filename)
    if m:
        return m.group("name"), m.group("version")

    m = _SIMPLE_WHL_RE.match(filename)
    if m:
        name = m.group("name").replace("_", "-")
        return name, m.group("version")

    return None


class HashVerifier:
    """Verifies artifact hashes against PyPI's recorded digests"""

    def verify(self, artifact_path: Path | str) -> dict[str, Any]:
        """Verify artifact hash against PyPI"""
        artifact_path = Path(artifact_path)

        # Extract package name and version from artifact filename
        filename = artifact_path.name
        parsed = _parse_artifact_filename(filename)
        if not parsed:
            return {"error": "Could not parse package name and version from filename"}
        package_name, version = parsed

        # Calculate hash
        try:
            calculated_hash = calculate_hash(artifact_path, "sha256")
        except Exception as e:
            return {"error": f"Failed to calculate hash: {e}"}

        # Fetch expected hash from PyPI
        try:
            with PyPIClient() as pypi:
                metadata = pypi.get_package_metadata(package_name, version)
                # PyPI JSON API includes file hashes in releases
                releases = metadata.get("releases", {}).get(version, [])
                for file_info in releases:
                    if file_info.get("filename") == filename:
                        expected_hash = file_info.get("digests", {}).get("sha256")
                        if expected_hash:
                            matches = calculated_hash.lower() == expected_hash.lower()
                            return {
                                "algorithm": "sha256",
                                "calculated": calculated_hash,
                                "expected": expected_hash,
                                "matches": matches,
                                "status": "verified" if matches else "mismatch",
                            }
        except Exception as e:
            return {"error": f"Failed to fetch expected hash: {e}"}

        return {"error": "Hash information not found on PyPI"}
