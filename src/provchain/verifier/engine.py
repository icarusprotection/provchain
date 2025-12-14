"""Verifier engine: Provenance verification orchestrator"""

from pathlib import Path
from typing import Any

from provchain.data.models import PackageIdentifier
from provchain.verifier.provenance.hash import HashVerifier
from provchain.verifier.provenance.sigstore import SigstoreVerifier


class VerifierEngine:
    """Main orchestrator for provenance verification"""

    def __init__(self):
        self.hash_verifier = HashVerifier()
        self.sigstore_verifier = SigstoreVerifier()

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

        return results

    def verify_package(self, package_identifier: PackageIdentifier) -> dict[str, Any]:
        """Verify an installed package"""
        import importlib.util
        import site
        from pathlib import Path
        
        package_name = package_identifier.name
        version = package_identifier.version
        
        results: dict[str, Any] = {
            "package": str(package_identifier),
            "verifications": {},
        }
        
        # Try to locate installed package
        try:
            spec = importlib.util.find_spec(package_name)
            if spec is None or spec.origin is None:
                results["verifications"]["location"] = {
                    "status": "not_found",
                    "note": f"Package {package_name} is not installed",
                }
                return results
            
            package_path = Path(spec.origin)
            
            # Try to find the installed package's distribution metadata
            # Look in site-packages for .dist-info or .egg-info
            site_packages = Path(site.getsitepackages()[0] if site.getsitepackages() else "")
            
            dist_info = None
            for dist_dir in site_packages.glob(f"{package_name.replace('-', '_')}-*.dist-info"):
                dist_info = dist_dir
                break
            
            if not dist_info:
                for dist_dir in site_packages.glob(f"{package_name.replace('-', '_')}-*.egg-info"):
                    dist_info = dist_dir
                    break
            
            if dist_info:
                # Try to verify the installed package
                # For installed packages, we can check metadata
                metadata_file = dist_info / "METADATA"
                if metadata_file.exists():
                    results["verifications"]["metadata"] = {
                        "status": "found",
                        "path": str(metadata_file),
                    }
                    
                    # Try hash verification if we can locate the wheel/sdist
                    # This is limited for installed packages
                    results["verifications"]["hash"] = {
                        "status": "limited",
                        "note": "Hash verification for installed packages requires original artifact",
                    }
                else:
                    results["verifications"]["metadata"] = {
                        "status": "not_found",
                    }
            else:
                results["verifications"]["location"] = {
                    "status": "found",
                    "path": str(package_path),
                    "note": "Package found but distribution metadata not located",
                }
                
        except Exception as e:
            results["verifications"]["error"] = {
                "status": "error",
                "error": str(e),
            }
        
        return results

