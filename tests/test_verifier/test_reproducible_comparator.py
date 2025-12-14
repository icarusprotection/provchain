"""Tests for artifact comparator"""

import hashlib
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import tarfile

from provchain.verifier.reproducible.comparator import ArtifactComparator


class TestArtifactComparator:
    """Test cases for ArtifactComparator"""

    def test_artifact_comparator_init(self):
        """Test ArtifactComparator initialization"""
        comparator = ArtifactComparator()
        assert comparator is not None

    def test_compare_artifact1_not_found(self, tmp_path):
        """Test compare when artifact1 doesn't exist"""
        artifact1 = tmp_path / "nonexistent1.whl"
        artifact2 = tmp_path / "artifact2.whl"
        artifact2.touch()
        
        comparator = ArtifactComparator()
        result = comparator.compare(artifact1, artifact2)
        
        assert result["status"] == "error"
        assert "Artifact 1 not found" in result["error"]

    def test_compare_artifact2_not_found(self, tmp_path):
        """Test compare when artifact2 doesn't exist"""
        artifact1 = tmp_path / "artifact1.whl"
        artifact1.touch()
        artifact2 = tmp_path / "nonexistent2.whl"
        
        comparator = ArtifactComparator()
        result = comparator.compare(artifact1, artifact2)
        
        assert result["status"] == "error"
        assert "Artifact 2 not found" in result["error"]

    @patch('provchain.verifier.reproducible.comparator.calculate_hash')
    def test_compare_identical_hashes(self, mock_calculate_hash, tmp_path):
        """Test compare when hashes are identical"""
        artifact1 = tmp_path / "artifact1.whl"
        artifact1.touch()
        artifact2 = tmp_path / "artifact2.whl"
        artifact2.touch()
        
        # Mock hash calculation to return same hash
        mock_calculate_hash.return_value = "abc123"
        
        comparator = ArtifactComparator()
        result = comparator.compare(artifact1, artifact2)
        
        assert result["status"] == "identical"
        assert "byte-for-byte identical" in result["note"]

    @patch('provchain.verifier.reproducible.comparator.calculate_hash')
    def test_compare_hash_calculation_error(self, mock_calculate_hash, tmp_path):
        """Test compare when hash calculation fails"""
        artifact1 = tmp_path / "artifact1.whl"
        artifact1.touch()
        artifact2 = tmp_path / "artifact2.whl"
        artifact2.touch()
        
        # Mock hash calculation to raise exception
        mock_calculate_hash.side_effect = Exception("Hash calculation failed")
        
        comparator = ArtifactComparator()
        result = comparator.compare(artifact1, artifact2)
        
        assert result["status"] == "error"
        assert "Failed to calculate hashes" in result["error"]

    def test_compare_whl_files_identical(self, tmp_path):
        """Test compare identical .whl files"""
        # Create two identical zip files
        artifact1 = tmp_path / "artifact1.whl"
        artifact2 = tmp_path / "artifact2.whl"
        
        content = b"test content"
        content_hash = hashlib.sha256(content).hexdigest()
        
        with zipfile.ZipFile(artifact1, 'w') as zf:
            zf.writestr("file1.txt", content)
        
        with zipfile.ZipFile(artifact2, 'w') as zf:
            zf.writestr("file1.txt", content)
        
        # Mock calculate_hash to return different hashes (so it goes to content comparison)
        with patch('provchain.verifier.reproducible.comparator.calculate_hash') as mock_hash:
            mock_hash.side_effect = ["hash1", "hash2"]  # Different file hashes
            
            comparator = ArtifactComparator()
            result = comparator.compare(artifact1, artifact2)
            
            assert result["status"] == "compared"
            assert result["identical"] is True
            assert len(result["differences"]) == 0

    def test_compare_whl_files_different(self, tmp_path):
        """Test compare different .whl files"""
        # Create two different zip files
        artifact1 = tmp_path / "artifact1.whl"
        artifact2 = tmp_path / "artifact2.whl"
        
        with zipfile.ZipFile(artifact1, 'w') as zf:
            zf.writestr("file1.txt", b"content1")
        
        with zipfile.ZipFile(artifact2, 'w') as zf:
            zf.writestr("file1.txt", b"content2")
        
        # Mock calculate_hash to return different hashes
        with patch('provchain.verifier.reproducible.comparator.calculate_hash') as mock_hash:
            mock_hash.side_effect = ["hash1", "hash2"]
            
            comparator = ArtifactComparator()
            result = comparator.compare(artifact1, artifact2)
            
            assert result["status"] == "compared"
            assert result["identical"] is False
            assert len(result["differences"]) > 0

    def test_compare_tar_files_identical(self, tmp_path):
        """Test compare identical .tar.gz files"""
        artifact1 = tmp_path / "artifact1.tar.gz"
        artifact2 = tmp_path / "artifact2.tar.gz"
        
        content = b"test content"
        
        # Create tar.gz files properly
        with tarfile.open(artifact1, 'w:gz') as tar:
            file_obj = tempfile.NamedTemporaryFile(delete=False)
            file_obj.write(content)
            file_obj.seek(0)
            tarinfo = tar.gettarinfo(file_obj.name, arcname="file1.txt")
            tar.addfile(tarinfo, file_obj)
            file_obj.close()
        
        with tarfile.open(artifact2, 'w:gz') as tar:
            file_obj = tempfile.NamedTemporaryFile(delete=False)
            file_obj.write(content)
            file_obj.seek(0)
            tarinfo = tar.gettarinfo(file_obj.name, arcname="file1.txt")
            tar.addfile(tarinfo, file_obj)
            file_obj.close()
        
        # Mock calculate_hash to return different hashes
        with patch('provchain.verifier.reproducible.comparator.calculate_hash') as mock_hash:
            mock_hash.side_effect = ["hash1", "hash2"]
            
            comparator = ArtifactComparator()
            result = comparator.compare(artifact1, artifact2)
            
            assert result["status"] == "compared"

    def test_compare_files_only_in_1(self, tmp_path):
        """Test compare when files exist only in artifact1"""
        artifact1 = tmp_path / "artifact1.whl"
        artifact2 = tmp_path / "artifact2.whl"
        
        with zipfile.ZipFile(artifact1, 'w') as zf:
            zf.writestr("file1.txt", b"content1")
            zf.writestr("file2.txt", b"content2")
        
        with zipfile.ZipFile(artifact2, 'w') as zf:
            zf.writestr("file1.txt", b"content1")
        
        with patch('provchain.verifier.reproducible.comparator.calculate_hash') as mock_hash:
            mock_hash.side_effect = ["hash1", "hash2"]
            
            comparator = ArtifactComparator()
            result = comparator.compare(artifact1, artifact2)
            
            assert result["status"] == "compared"
            assert any("Files only in artifact 1" in d for d in result["differences"])

    def test_compare_files_only_in_2(self, tmp_path):
        """Test compare when files exist only in artifact2"""
        artifact1 = tmp_path / "artifact1.whl"
        artifact2 = tmp_path / "artifact2.whl"
        
        with zipfile.ZipFile(artifact1, 'w') as zf:
            zf.writestr("file1.txt", b"content1")
        
        with zipfile.ZipFile(artifact2, 'w') as zf:
            zf.writestr("file1.txt", b"content1")
            zf.writestr("file2.txt", b"content2")
        
        with patch('provchain.verifier.reproducible.comparator.calculate_hash') as mock_hash:
            mock_hash.side_effect = ["hash1", "hash2"]
            
            comparator = ArtifactComparator()
            result = comparator.compare(artifact1, artifact2)
            
            assert result["status"] == "compared"
            assert any("Files only in artifact 2" in d for d in result["differences"])

    def test_compare_common_files_differ(self, tmp_path):
        """Test compare when common files differ"""
        artifact1 = tmp_path / "artifact1.whl"
        artifact2 = tmp_path / "artifact2.whl"
        
        with zipfile.ZipFile(artifact1, 'w') as zf:
            zf.writestr("file1.txt", b"content1")
        
        with zipfile.ZipFile(artifact2, 'w') as zf:
            zf.writestr("file1.txt", b"content2")
        
        with patch('provchain.verifier.reproducible.comparator.calculate_hash') as mock_hash:
            mock_hash.side_effect = ["hash1", "hash2"]
            
            comparator = ArtifactComparator()
            result = comparator.compare(artifact1, artifact2)
            
            assert result["status"] == "compared"
            assert any("File file1.txt differs" in d for d in result["differences"])

    def test_compare_difference_limit(self, tmp_path):
        """Test compare when difference limit is reached"""
        artifact1 = tmp_path / "artifact1.whl"
        artifact2 = tmp_path / "artifact2.whl"
        
        # Create many different files
        with zipfile.ZipFile(artifact1, 'w') as zf:
            for i in range(25):
                zf.writestr(f"file{i}.txt", b"content1")
        
        with zipfile.ZipFile(artifact2, 'w') as zf:
            for i in range(25):
                zf.writestr(f"file{i}.txt", b"content2")
        
        with patch('provchain.verifier.reproducible.comparator.calculate_hash') as mock_hash:
            mock_hash.side_effect = ["hash1", "hash2"]
            
            comparator = ArtifactComparator()
            result = comparator.compare(artifact1, artifact2)
            
            assert result["status"] == "compared"
            assert any("... (more differences)" in d for d in result["differences"])

    @patch('provchain.verifier.reproducible.comparator.zipfile.ZipFile')
    def test_compare_extraction_error(self, mock_zipfile, tmp_path):
        """Test compare when extraction fails"""
        artifact1 = tmp_path / "artifact1.whl"
        artifact1.touch()
        artifact2 = tmp_path / "artifact2.whl"
        artifact2.touch()
        
        # Mock zipfile to raise exception
        mock_zipfile.side_effect = Exception("Extraction error")
        
        with patch('provchain.verifier.reproducible.comparator.calculate_hash') as mock_hash:
            mock_hash.side_effect = ["hash1", "hash2"]
            
            comparator = ArtifactComparator()
            result = comparator.compare(artifact1, artifact2)
            
            assert result["status"] == "error"
            assert "Extraction error" in result["error"]

    def test_extract_file_list_whl(self, tmp_path):
        """Test _extract_file_list for .whl files"""
        artifact = tmp_path / "test.whl"
        
        content = b"test content"
        content_hash = hashlib.sha256(content).hexdigest()
        
        with zipfile.ZipFile(artifact, 'w') as zf:
            zf.writestr("file1.txt", content)
            zf.writestr("dir/", b"")  # Directory entry
        
        comparator = ArtifactComparator()
        files = comparator._extract_file_list(artifact)
        
        assert "file1.txt" in files
        assert files["file1.txt"] == content_hash
        assert "dir/" not in files  # Directories should be excluded

    def test_extract_file_list_zip(self, tmp_path):
        """Test _extract_file_list for .zip files"""
        artifact = tmp_path / "test.zip"
        
        content = b"test content"
        content_hash = hashlib.sha256(content).hexdigest()
        
        with zipfile.ZipFile(artifact, 'w') as zf:
            zf.writestr("file1.txt", content)
        
        comparator = ArtifactComparator()
        files = comparator._extract_file_list(artifact)
        
        assert "file1.txt" in files
        assert files["file1.txt"] == content_hash

    def test_extract_file_list_tar(self, tmp_path):
        """Test _extract_file_list for .tar.gz files"""
        artifact = tmp_path / "test.tar.gz"
        
        content = b"test content"
        content_hash = hashlib.sha256(content).hexdigest()
        
        # Create a simple tar.gz file
        with tarfile.open(artifact, 'w:gz') as tar:
            # Create a file in the tar
            file_obj = tempfile.NamedTemporaryFile(delete=False)
            file_obj.write(content)
            file_obj.seek(0)
            tarinfo = tar.gettarinfo(file_obj.name, arcname="file1.txt")
            tar.addfile(tarinfo, file_obj)
            file_obj.close()
        
        comparator = ArtifactComparator()
        files = comparator._extract_file_list(artifact)
        
        assert "file1.txt" in files
        assert files["file1.txt"] == content_hash

    def test_compare_with_string_paths(self, tmp_path):
        """Test compare with string paths instead of Path objects"""
        artifact1 = tmp_path / "artifact1.whl"
        artifact2 = tmp_path / "artifact2.whl"
        artifact1.touch()
        artifact2.touch()
        
        with patch('provchain.verifier.reproducible.comparator.calculate_hash') as mock_hash:
            mock_hash.return_value = "same_hash"
            
            comparator = ArtifactComparator()
            result = comparator.compare(str(artifact1), str(artifact2))
            
            assert result["status"] == "identical"

