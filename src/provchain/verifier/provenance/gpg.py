"""GPG signature verification"""

import subprocess
from pathlib import Path
from typing import Any


class GPGVerifier:
    """GPG signature verification"""

    def verify(self, artifact_path: Path | str, signature_path: Path | str | None = None) -> dict[str, Any]:
        """Verify GPG signature"""
        artifact_path = Path(artifact_path)
        
        # Find signature file
        if signature_path is None:
            # Try common signature file names
            for ext in [".asc", ".sig", ".gpg"]:
                candidate = artifact_path.with_suffix(artifact_path.suffix + ext)
                if candidate.exists():
                    signature_path = candidate
                    break
        
        if signature_path is None:
            # Try .asc file with same base name
            asc_path = artifact_path.with_suffix(".asc")
            if asc_path.exists():
                signature_path = asc_path
        
        if signature_path is None or not Path(signature_path).exists():
            return {
                "available": False,
                "status": "no_signature",
                "note": "No GPG signature file found",
            }
        
        # Check if GPG is available
        try:
            result = subprocess.run(
                ["gpg", "--version"],
                capture_output=True,
                timeout=5,
            )
            if result.returncode != 0:
                return {
                    "available": False,
                    "status": "gpg_unavailable",
                    "note": "GPG is not available or not working",
                }
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return {
                "available": False,
                "status": "gpg_not_installed",
                "note": "GPG is not installed",
            }
        
        # Verify signature
        try:
            result = subprocess.run(
                ["gpg", "--verify", str(signature_path), str(artifact_path)],
                capture_output=True,
                timeout=30,
            )
            
            if result.returncode == 0:
                return {
                    "available": True,
                    "status": "verified",
                    "signature_file": str(signature_path),
                    "note": "GPG signature verified successfully",
                }
            else:
                # Parse output for more details
                output = result.stderr.decode("utf-8", errors="ignore")
                return {
                    "available": True,
                    "status": "verification_failed",
                    "signature_file": str(signature_path),
                    "error": output,
                    "note": "GPG signature verification failed",
                }
        except subprocess.TimeoutExpired:
            return {
                "available": True,
                "status": "timeout",
                "note": "GPG verification timed out",
            }
        except Exception as e:
            return {
                "available": True,
                "status": "error",
                "error": str(e),
            }

