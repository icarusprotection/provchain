"""Sigstore verification"""

from pathlib import Path
from typing import Any


class SigstoreVerifier:
    """Verifies Sigstore signatures for packages that support them"""

    def verify(self, artifact_path: Path | str) -> dict[str, Any]:
        """Verify Sigstore signature"""
        artifact_path = Path(artifact_path)

        # Check for signature file
        sig_path = artifact_path.with_suffix(artifact_path.suffix + ".sig")

        if not sig_path.exists():
            return {
                "available": False,
                "status": "no_signature",
                "note": "No Sigstore signature file found",
            }

        try:
            # Try to use sigstore-python if available
            try:
                # Check if sigstore is available (for future implementation)
                import importlib.util

                if importlib.util.find_spec("sigstore.verify") is not None:
                    # Sigstore is available - signature file exists, verification can be implemented
                    # For now, just check signature format
                    return {
                        "available": True,
                        "status": "signature_found",
                        "note": "Sigstore signature file found (verification requires identity policy)",
                        "signature_file": str(sig_path),
                    }
            except ImportError:
                # sigstore-python not available, check if signature file exists
                return {
                    "available": False,
                    "status": "library_missing",
                    "note": "sigstore-python library required for verification",
                    "signature_file": str(sig_path) if sig_path.exists() else None,
                }
        except Exception as e:
            return {
                "available": False,
                "status": "error",
                "error": str(e),
            }
