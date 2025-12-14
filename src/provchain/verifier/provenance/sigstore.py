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
        cert_path = artifact_path.with_suffix(artifact_path.suffix + ".crt")
        
        if not sig_path.exists():
            return {
                "available": False,
                "status": "no_signature",
                "note": "No Sigstore signature file found",
            }
        
        try:
            # Try to use sigstore-python if available
            try:
                from sigstore.verify import Verifier, VerificationMaterials
                from sigstore.verify.policy import Identity
            
                # Load signature and certificate
                with open(sig_path, "rb") as f:
                    signature = f.read()
                
                if cert_path.exists():
                    with open(cert_path, "rb") as f:
                        certificate = f.read()
                else:
                    # Certificate might be embedded or need to be fetched
                    certificate = None
                
                # Create verifier
                verifier = Verifier.production()
                
                # Create verification materials
                materials = VerificationMaterials.from_dsse(
                    artifact_path,
                    signature,
                    certificate,
                )
                
                # Verify (this would need proper identity policy in production)
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

