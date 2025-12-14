"""Binary artifact comparison"""

import zipfile
from pathlib import Path
from typing import Any

import tarfile

from provchain.utils.hashing import calculate_hash


class ArtifactComparator:
    """Compare binary artifacts"""

    def compare(self, artifact1: Path | str, artifact2: Path | str) -> dict[str, Any]:
        """Compare two artifacts and report differences"""
        artifact1 = Path(artifact1)
        artifact2 = Path(artifact2)
        
        if not artifact1.exists():
            return {
                "status": "error",
                "error": f"Artifact 1 not found: {artifact1}",
            }
        
        if not artifact2.exists():
            return {
                "status": "error",
                "error": f"Artifact 2 not found: {artifact2}",
            }
        
        # Compare hashes first (quick check)
        try:
            hash1 = calculate_hash(artifact1, "sha256")
            hash2 = calculate_hash(artifact2, "sha256")
            
            if hash1 == hash2:
                return {
                    "status": "identical",
                    "note": "Artifacts are byte-for-byte identical",
                }
        except Exception as e:
            return {
                "status": "error",
                "error": f"Failed to calculate hashes: {e}",
            }
        
        # Extract and compare contents
        differences = []
        
        try:
            # Extract both artifacts
            files1 = self._extract_file_list(artifact1)
            files2 = self._extract_file_list(artifact2)
            
            # Compare file lists
            only_in_1 = set(files1.keys()) - set(files2.keys())
            only_in_2 = set(files2.keys()) - set(files1.keys())
            common = set(files1.keys()) & set(files2.keys())
            
            if only_in_1:
                differences.append(f"Files only in artifact 1: {list(only_in_1)[:10]}")
            if only_in_2:
                differences.append(f"Files only in artifact 2: {list(only_in_2)[:10]}")
            
            # Compare common files (ignoring timestamps in zip metadata)
            for filename in common:
                if files1[filename] != files2[filename]:
                    differences.append(f"File {filename} differs")
                    if len(differences) >= 20:  # Limit output
                        differences.append("... (more differences)")
                        break
            
            return {
                "status": "compared",
                "identical": len(differences) == 0,
                "differences": differences,
                "files_in_1": len(files1),
                "files_in_2": len(files2),
                "common_files": len(common),
            }
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
            }
    
    def _extract_file_list(self, artifact_path: Path) -> dict[str, str]:
        """Extract file list and hashes from artifact"""
        files = {}
        
        if artifact_path.suffix == ".whl" or artifact_path.suffix == ".zip":
            with zipfile.ZipFile(artifact_path) as zipf:
                for info in zipf.infolist():
                    if not info.is_dir():
                        # Read file content and hash (ignoring timestamp)
                        content = zipf.read(info.filename)
                        import hashlib
                        file_hash = hashlib.sha256(content).hexdigest()
                        files[info.filename] = file_hash
        elif artifact_path.suffix == ".gz" or artifact_path.name.endswith(".tar.gz"):
            with tarfile.open(artifact_path) as tar:
                for member in tar.getmembers():
                    if member.isfile():
                        content = tar.extractfile(member)
                        if content:
                            import hashlib
                            file_hash = hashlib.sha256(content.read()).hexdigest()
                            files[member.name] = file_hash
        
        return files

