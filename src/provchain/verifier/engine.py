"""Verifier engine: Provenance verification orchestrator"""

import csv
import hashlib
import logging
import tempfile
from pathlib import Path
from typing import Any

from provchain.data.models import PackageIdentifier
from provchain.integrations.pypi import PyPIClient
from provchain.verifier.provenance.gpg import GPGVerifier
from provchain.verifier.provenance.hash import HashVerifier
from provchain.verifier.provenance.sigstore import SigstoreVerifier

logger = logging.getLogger(__name__)


class VerifierEngine:
    """Main orchestrator for provenance verification"""

    def __init__(self):
        self.hash_verifier = HashVerifier()
        self.sigstore_verifier = SigstoreVerifier()
        self.gpg_verifier = GPGVerifier()

    def verify_artifact(self, artifact_path: Path | str) -> dict[str, Any]:
        """Verify an artifact (wheel, sdist, or installed package)"""
        artifact_path = Path(artifact_path)
        results: dict[str, Any] = {
            "artifact": str(artifact_path),
            "verifications": {},
        }

        # Hash verification
        try:
            hash_result = self.hash_verifier.verify(artifact_path)
            results["verifications"]["hash"] = hash_result
        except Exception as e:
            results["verifications"]["hash"] = {"error": str(e)}

        # Sigstore verification (if available)
        try:
            sigstore_result = self.sigstore_verifier.verify(artifact_path)
            results["verifications"]["sigstore"] = sigstore_result
        except Exception as e:
            results["verifications"]["sigstore"] = {"error": str(e), "available": False}

        # GPG verification (if available)
        try:
            gpg_result = self.gpg_verifier.verify(artifact_path)
            results["verifications"]["gpg"] = gpg_result
        except Exception as e:
            results["verifications"]["gpg"] = {"error": str(e), "available": False}

        return results

    def _verify_record_file(self, dist_info: Path) -> dict[str, Any]:
        """Verify installed file integrity using the RECORD file from dist-info.

        The RECORD file lists every installed file along with its hash
        (algorithm=digest) and size. This method re-hashes each file and
        compares against the recorded digest.
        """
        record_path = dist_info / "RECORD"
        if not record_path.exists():
            return {
                "status": "not_found",
                "note": "No RECORD file found in dist-info",
            }

        site_packages = dist_info.parent
        total = 0
        verified = 0
        mismatched = 0
        missing = 0
        skipped = 0
        mismatches: list[dict[str, str]] = []

        try:
            with open(record_path, newline="", encoding="utf-8") as f:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) < 2:
                        continue
                    rel_path = row[0]
                    hash_spec = row[1]

                    # RECORD itself and .pyc files have no hash recorded
                    if not hash_spec:
                        skipped += 1
                        continue

                    total += 1
                    file_path = site_packages / rel_path

                    if not file_path.exists():
                        missing += 1
                        continue

                    # hash_spec is like "sha256=base64digest"
                    try:
                        algo, expected_b64 = hash_spec.split("=", 1)
                    except ValueError:
                        skipped += 1
                        continue

                    import base64

                    try:
                        h = hashlib.new(algo)
                    except ValueError:
                        skipped += 1
                        continue

                    with open(file_path, "rb") as fh:
                        for chunk in iter(lambda: fh.read(8192), b""):
                            h.update(chunk)

                    calculated_b64 = (
                        base64.urlsafe_b64encode(h.digest()).rstrip(b"=").decode("ascii")
                    )

                    if calculated_b64 == expected_b64:
                        verified += 1
                    else:
                        mismatched += 1
                        mismatches.append(
                            {
                                "file": rel_path,
                                "expected": expected_b64,
                                "calculated": calculated_b64,
                            }
                        )

        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
            }

        status = "verified" if mismatched == 0 and missing == 0 else "integrity_errors"
        result: dict[str, Any] = {
            "status": status,
            "total_files": total,
            "verified": verified,
            "mismatched": mismatched,
            "missing": missing,
            "skipped": skipped,
        }
        if mismatches:
            result["mismatches"] = mismatches[:20]  # Limit output
        return result

    def _find_dist_info(self, package_name: str) -> Path | None:
        """Locate the dist-info directory for an installed package."""
        import site

        site_packages_dirs = site.getsitepackages() if hasattr(site, "getsitepackages") else []
        user_site = getattr(site, "getusersitepackages", lambda: None)()
        if user_site:
            site_packages_dirs.append(user_site)

        normalized = package_name.replace("-", "_")
        for sp in site_packages_dirs:
            sp_path = Path(sp)
            if not sp_path.is_dir():
                continue
            for dist_dir in sp_path.glob(f"{normalized}-*.dist-info"):
                return dist_dir
            for dist_dir in sp_path.glob(f"{normalized}-*.egg-info"):
                return dist_dir
        return None

    def verify_package(self, package_identifier: PackageIdentifier) -> dict[str, Any]:
        """Verify an installed package against PyPI's published digests."""
        import importlib.util

        package_name = package_identifier.name
        version = package_identifier.version

        results: dict[str, Any] = {
            "package": str(package_identifier),
            "verifications": {},
        }

        # --- Locate the installed package ---
        try:
            spec = importlib.util.find_spec(package_name.replace("-", "_"))
            if spec is None or spec.origin is None:
                results["verifications"]["location"] = {
                    "status": "not_found",
                    "note": f"Package {package_name} is not installed",
                }
                return results

            package_path = Path(spec.origin)
            results["verifications"]["location"] = {
                "status": "found",
                "path": str(package_path),
            }
        except Exception as e:
            results["verifications"]["location"] = {
                "status": "error",
                "error": str(e),
            }

        # --- Verify installed files via RECORD ---
        dist_info = self._find_dist_info(package_name)
        if dist_info:
            metadata_file = dist_info / "METADATA"
            results["verifications"]["metadata"] = {
                "status": "found" if metadata_file.exists() else "not_found",
                "path": str(metadata_file) if metadata_file.exists() else None,
            }

            record_result = self._verify_record_file(dist_info)
            results["verifications"]["record_integrity"] = record_result
        else:
            results["verifications"]["metadata"] = {
                "status": "not_found",
                "note": "Distribution metadata directory not located",
            }

        # --- Fetch package info from PyPI and verify against published digests ---
        pypi_files: list[dict[str, Any]] = []
        try:
            with PyPIClient() as pypi:
                metadata = pypi.get_package_metadata(package_name, version)

            # PyPI version-specific endpoint puts files under "urls" key
            pypi_files = metadata.get("urls", [])
            # Fallback: also check releases dict
            if not pypi_files:
                pypi_files = metadata.get("releases", {}).get(version, [])

            if pypi_files:
                results["verifications"]["pypi_published"] = {
                    "status": "found",
                    "files": len(pypi_files),
                    "digests_available": any(
                        f.get("digests", {}).get("sha256") for f in pypi_files
                    ),
                }
            else:
                results["verifications"]["pypi_published"] = {
                    "status": "no_files",
                    "note": f"No release files found on PyPI for {package_name}=={version}",
                }

        except Exception as e:
            logger.warning("Failed to fetch PyPI metadata for %s==%s: %s", package_name, version, e)
            results["verifications"]["pypi_published"] = {
                "status": "error",
                "error": str(e),
            }

        # --- Download the artifact from PyPI and verify its hash ---
        if pypi_files:
            # Prefer a wheel, fall back to sdist
            chosen_file = None
            for f in pypi_files:
                if f.get("filename", "").endswith(".whl"):
                    chosen_file = f
                    break
            if chosen_file is None:
                chosen_file = pypi_files[0]

            download_url = chosen_file.get("url")
            expected_sha256 = chosen_file.get("digests", {}).get("sha256")
            filename = chosen_file.get("filename", "artifact")

            if download_url and expected_sha256:
                try:
                    import httpx

                    with tempfile.TemporaryDirectory() as tmp_dir:
                        tmp_path = Path(tmp_dir) / filename

                        # Download the artifact
                        logger.info("Downloading %s from PyPI for verification...", filename)
                        with httpx.Client(follow_redirects=True, timeout=60) as client:
                            resp = client.get(download_url)
                            resp.raise_for_status()
                            tmp_path.write_bytes(resp.content)

                        # Verify hash against PyPI's published digest
                        from provchain.utils.hashing import calculate_hash

                        calculated_sha256 = calculate_hash(tmp_path, "sha256")
                        hash_matches = calculated_sha256.lower() == expected_sha256.lower()

                        results["verifications"]["hash"] = {
                            "status": "verified" if hash_matches else "mismatch",
                            "algorithm": "sha256",
                            "calculated": calculated_sha256,
                            "expected": expected_sha256,
                            "matches": hash_matches,
                            "artifact": filename,
                        }

                        if not hash_matches:
                            logger.warning(
                                "Hash mismatch for %s: expected %s, got %s",
                                filename,
                                expected_sha256,
                                calculated_sha256,
                            )

                        # Sigstore verification on the downloaded artifact
                        try:
                            sigstore_result = self.sigstore_verifier.verify(tmp_path)
                            results["verifications"]["sigstore"] = sigstore_result
                        except Exception as e:
                            results["verifications"]["sigstore"] = {
                                "error": str(e),
                                "available": False,
                            }

                        # GPG verification on the downloaded artifact
                        try:
                            gpg_result = self.gpg_verifier.verify(tmp_path)
                            results["verifications"]["gpg"] = gpg_result
                        except Exception as e:
                            results["verifications"]["gpg"] = {
                                "error": str(e),
                                "available": False,
                            }

                except Exception as e:
                    logger.warning("Failed to download/verify artifact %s: %s", filename, e)
                    results["verifications"]["hash"] = {
                        "status": "error",
                        "error": str(e),
                        "note": "Failed to download artifact from PyPI for hash verification",
                    }
            else:
                results["verifications"]["hash"] = {
                    "status": "unavailable",
                    "note": "No download URL or SHA256 digest available from PyPI",
                }

        return results
