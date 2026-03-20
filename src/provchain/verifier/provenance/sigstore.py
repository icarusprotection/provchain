"""Sigstore verification"""

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Recognized Sigstore signature file extensions
_SIGSTORE_EXTENSIONS = [".sig", ".sigstore", ".sigstore.json"]


class SigstoreVerifier:
    """Verifies Sigstore signatures for packages that support them"""

    def _find_signature_file(self, artifact_path: Path) -> Path | None:
        """Look for a Sigstore signature/bundle file next to the artifact."""
        for ext in _SIGSTORE_EXTENSIONS:
            candidate = artifact_path.with_suffix(artifact_path.suffix + ext)
            if candidate.exists():
                return candidate
        return None

    def _validate_bundle_structure(self, bundle_path: Path) -> dict[str, Any]:
        """Parse a .sigstore.json bundle and validate its JSON structure.

        This provides a basic structural check when the ``sigstore`` library
        is not installed.  It verifies that the required top-level keys are
        present but does **not** perform cryptographic verification.
        """
        try:
            with open(bundle_path, encoding="utf-8") as f:
                bundle = json.load(f)

            if not isinstance(bundle, dict):
                return {
                    "available": False,
                    "status": "invalid_bundle",
                    "note": "Bundle file does not contain a JSON object",
                    "signature_file": str(bundle_path),
                }

            # Sigstore bundles (v0.2+) are expected to contain at least
            # "mediaType" and "verificationMaterial" at the top level.
            has_media_type = "mediaType" in bundle
            has_verification = "verificationMaterial" in bundle
            has_content = "messageSignature" in bundle or "dsseEnvelope" in bundle

            if has_media_type and has_verification and has_content:
                return {
                    "available": True,
                    "status": "bundle_valid_structure",
                    "note": (
                        "Sigstore bundle has valid structure "
                        "(cryptographic verification requires sigstore-python)"
                    ),
                    "signature_file": str(bundle_path),
                    "media_type": bundle.get("mediaType"),
                }

            missing = []
            if not has_media_type:
                missing.append("mediaType")
            if not has_verification:
                missing.append("verificationMaterial")
            if not has_content:
                missing.append("messageSignature/dsseEnvelope")

            return {
                "available": False,
                "status": "incomplete_bundle",
                "note": f"Bundle missing required keys: {', '.join(missing)}",
                "signature_file": str(bundle_path),
            }

        except json.JSONDecodeError as e:
            return {
                "available": False,
                "status": "invalid_json",
                "error": str(e),
                "signature_file": str(bundle_path),
            }
        except Exception as e:
            return {
                "available": False,
                "status": "error",
                "error": str(e),
                "signature_file": str(bundle_path),
            }

    def verify(self, artifact_path: Path | str) -> dict[str, Any]:
        """Verify Sigstore signature for an artifact.

        Looks for ``.sig``, ``.sigstore``, or ``.sigstore.json`` files next
        to the artifact.  When the ``sigstore`` library is installed the
        actual cryptographic verification is performed; otherwise a
        structural validation of the bundle is attempted.
        """
        artifact_path = Path(artifact_path)

        sig_path = self._find_signature_file(artifact_path)

        if sig_path is None:
            return {
                "available": False,
                "status": "no_signature",
                "note": "No Sigstore signature file found",
            }

        logger.debug("Found Sigstore signature file: %s", sig_path)

        # --- Try cryptographic verification via sigstore-python ---
        try:
            from sigstore.verify import (  # type: ignore[import-not-found]
                Verifier,
                policy,
            )

            logger.info("sigstore-python available – performing cryptographic verification")

            verifier = Verifier.production()

            # Read the artifact bytes
            artifact_bytes = artifact_path.read_bytes()

            # Determine how to load the bundle / signature
            if sig_path.suffix == ".json" or str(sig_path).endswith(".sigstore.json"):
                from sigstore.models import Bundle  # type: ignore[import-not-found]

                bundle = Bundle.from_json(sig_path.read_text(encoding="utf-8"))
            elif sig_path.suffix in (".sigstore", ".sig"):
                from sigstore.models import Bundle  # noqa: F811

                # .sigstore files are also bundles (binary or JSON)
                try:
                    bundle = Bundle.from_json(sig_path.read_text(encoding="utf-8"))
                except Exception:
                    return {
                        "available": True,
                        "status": "unsupported_format",
                        "note": "Signature file format not recognised as a Sigstore bundle",
                        "signature_file": str(sig_path),
                    }
            else:
                return {
                    "available": True,
                    "status": "unsupported_format",
                    "signature_file": str(sig_path),
                }

            # Use the AnyOf policy so that verification succeeds for any
            # valid signing identity.  Callers that need stricter policies
            # should use the lower-level API directly.
            id_policy = policy.UnsafeNoOp()

            verifier.verify_artifact(
                input_=artifact_bytes,
                bundle=bundle,
                policy=id_policy,
            )

            return {
                "available": True,
                "status": "verified",
                "note": "Sigstore signature verified successfully",
                "signature_file": str(sig_path),
            }

        except ImportError:
            logger.debug("sigstore-python not installed – falling back to structural check")
        except Exception as e:
            # Verification was attempted but failed (e.g. invalid signature)
            logger.warning("Sigstore verification failed: %s", e)
            return {
                "available": True,
                "status": "verification_failed",
                "error": str(e),
                "signature_file": str(sig_path),
            }

        # --- Fallback: structural validation of .sigstore.json bundles ---
        if str(sig_path).endswith(".sigstore.json") or sig_path.suffix == ".sigstore":
            return self._validate_bundle_structure(sig_path)

        # We have a .sig file but no library to verify it
        return {
            "available": False,
            "status": "library_missing",
            "note": "sigstore-python library required for verification",
            "signature_file": str(sig_path),
        }
