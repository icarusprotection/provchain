"""Hash verification"""

from pathlib import Path
from typing import Any

from provchain.integrations.pypi import PyPIClient
from provchain.utils.hashing import calculate_hash


class HashVerifier:
    """Verifies artifact hashes against PyPI's recorded digests"""

    def verify(self, artifact_path: Path | str) -> dict[str, Any]:
        """Verify artifact hash against PyPI"""
        artifact_path = Path(artifact_path)

        # Extract package name and version from artifact filename
        # This is simplified - production would need proper parsing
        filename = artifact_path.name
        # Assume format: package-version.whl or package-version.tar.gz
        parts = filename.replace(".whl", "").replace(".tar.gz", "").split("-")
        if len(parts) >= 2:
            package_name = "-".join(parts[:-1])
            version = parts[-1]
        else:
            return {"error": "Could not parse package name and version from filename"}

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

