"""Reproducible build attempts"""

import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from provchain.integrations.pypi import PyPIClient
from provchain.utils.hashing import calculate_hash
from provchain.utils.network import HTTPClient


class ReproducibleBuildChecker:
    """Attempts to rebuild package from source and compare"""

    def verify(self, package: str, version: str) -> dict[str, Any]:
        """Attempt to rebuild package and compare"""
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_path = Path(tmpdir)
                build_dir = tmp_path / "build"
                build_dir.mkdir()

                # Fetch source distribution
                with PyPIClient() as pypi:
                    metadata = pypi.get_package_metadata(package, version)
                    releases = metadata.get("releases", {}).get(version, [])

                    sdist = None
                    for file_info in releases:
                        filename = file_info.get("filename", "")
                        if filename.endswith(".tar.gz") or filename.endswith(".zip"):
                            sdist = file_info
                            break

                    if not sdist:
                        return {
                            "status": "no_source",
                            "note": "No source distribution available",
                        }

                    # Download source
                    sdist_url = sdist.get("url")
                    if not sdist_url:
                        return {
                            "status": "no_url",
                            "note": "Source distribution URL not available",
                        }

                    with HTTPClient() as client:
                        response = client.get(sdist_url)
                        sdist_file = build_dir / sdist["filename"]
                        sdist_file.write_bytes(response.content)

                    # Extract
                    extract_dir = build_dir / "source"
                    extract_dir.mkdir()

                    if sdist_file.suffix == ".gz":
                        with tarfile.open(sdist_file, "r:gz") as tar:
                            # Validate tar members to prevent path traversal attacks
                            def safe_members(tar_file):
                                extract_path = Path(extract_dir).resolve()
                                for member in tar_file.getmembers():
                                    # Normalize path and check for directory traversal
                                    member_path = Path(member.name)
                                    # Check for absolute paths or parent directory references
                                    if member_path.is_absolute() or ".." in member_path.parts:
                                        continue
                                    # Resolve to ensure it's within extract directory
                                    resolved = (extract_path / member_path).resolve()
                                    try:
                                        resolved.relative_to(extract_path)
                                    except ValueError:
                                        # Path outside extract directory, skip
                                        continue
                                    yield member

                            tar.extractall(extract_dir, members=safe_members(tar))
                    elif sdist_file.suffix == ".zip":
                        with zipfile.ZipFile(sdist_file) as zipf:
                            # Validate zip members to prevent path traversal attacks
                            extract_path = Path(extract_dir).resolve()
                            for member in zipf.namelist():
                                # Normalize path and check for directory traversal
                                member_path = Path(member)
                                # Check for absolute paths or parent directory references
                                if member_path.is_absolute() or ".." in member_path.parts:
                                    continue
                                # Resolve to ensure it's within extract directory
                                resolved = (extract_path / member_path).resolve()
                                try:
                                    resolved.relative_to(extract_path)
                                except ValueError:
                                    # Path outside extract directory, skip
                                    continue
                                zipf.extract(member, extract_dir)

                    # Find package directory
                    extracted_dirs = [d for d in extract_dir.iterdir() if d.is_dir()]
                    if not extracted_dirs:
                        return {
                            "status": "extraction_failed",
                            "note": "Could not extract source distribution",
                        }

                    source_dir = extracted_dirs[0]

                    # Build package
                    try:
                        result = subprocess.run(
                            ["python", "-m", "build", "--wheel", "--outdir", str(build_dir)],
                            cwd=source_dir,
                            capture_output=True,
                            timeout=300,
                        )

                        if result.returncode != 0:
                            return {
                                "status": "build_failed",
                                "error": result.stderr.decode("utf-8", errors="ignore"),
                                "note": "Failed to build package from source",
                            }

                        # Find built wheel
                        wheels = list(build_dir.glob("*.whl"))
                        if not wheels:
                            return {
                                "status": "no_wheel",
                                "note": "Build succeeded but no wheel found",
                            }

                        built_wheel = wheels[0]

                        # Get original wheel hash from PyPI
                        original_wheel = None
                        for file_info in releases:
                            if file_info.get("filename", "").endswith(".whl"):
                                original_wheel = file_info
                                break

                        if original_wheel:
                            original_hash = original_wheel.get("digests", {}).get("sha256")
                            built_hash = calculate_hash(built_wheel, "sha256")

                            if original_hash and built_hash:
                                matches = original_hash.lower() == built_hash.lower()
                                return {
                                    "status": "compared",
                                    "reproducible": matches,
                                    "original_hash": original_hash,
                                    "built_hash": built_hash,
                                    "note": "Package is reproducible"
                                    if matches
                                    else "Package is not reproducible",
                                }

                        return {
                            "status": "built",
                            "note": "Package built successfully but comparison not available",
                        }

                    except subprocess.TimeoutExpired:
                        return {
                            "status": "timeout",
                            "note": "Build process timed out",
                        }
                    except FileNotFoundError:
                        return {
                            "status": "build_tools_missing",
                            "note": "Python build module not available",
                        }

        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "note": "Error during reproducible build check",
            }
