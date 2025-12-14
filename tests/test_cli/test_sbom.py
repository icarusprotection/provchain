"""Tests for SBOM CLI command"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch
from typer.testing import CliRunner

from provchain.cli.commands.sbom import app


@pytest.fixture
def runner():
    """CLI test runner"""
    return CliRunner()


def test_sbom_generate_help(runner):
    """Test SBOM generate command help"""
    result = runner.invoke(app, ["generate", "--help"])
    assert result.exit_code == 0
    assert "Generate SBOM" in result.stdout or "SBOM" in result.stdout


def test_sbom_generate_with_requirements(runner, tmp_path):
    """Test generating SBOM from requirements file"""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.31.0\n")
    output_file = tmp_path / "sbom.json"
    
    with patch('provchain.cli.commands.sbom.Database') as mock_db_class:
        mock_db = Mock()
        mock_db_class.return_value = mock_db
        
        result = runner.invoke(app, [
            "generate",
            "--requirements", str(req_file),
            "--output", str(output_file),
            "--name", "test-project"
        ])
        
        assert result.exit_code == 0
        assert output_file.exists()
        assert "SBOM generated" in result.stdout
        mock_db.store_sbom.assert_called_once()


def test_sbom_generate_without_requirements(runner):
    """Test generating SBOM without requirements file"""
    result = runner.invoke(app, ["generate"])
    
    assert result.exit_code == 0
    assert "Error" in result.stdout or "required" in result.stdout.lower()


def test_sbom_import_success(runner, tmp_path):
    """Test importing existing SBOM"""
    sbom_file = tmp_path / "sbom.json"
    sbom_file.write_text('''{
        "name": "test-project",
        "version": "1.0.0",
        "packages": [
            {
                "ecosystem": "pypi",
                "name": "requests",
                "version": "2.31.0"
            }
        ]
    }''')
    
    with patch('provchain.cli.commands.sbom.Database') as mock_db_class:
        mock_db = Mock()
        mock_db_class.return_value = mock_db
        
        result = runner.invoke(app, ["import-sbom", str(sbom_file)])
        
        assert result.exit_code == 0
        assert "Imported SBOM" in result.stdout
        assert "1 packages" in result.stdout
        mock_db.store_sbom.assert_called_once()


def test_sbom_import_file_not_found(runner):
    """Test importing SBOM from non-existent file"""
    result = runner.invoke(app, ["import-sbom", "nonexistent.json"])
    
    assert result.exit_code == 0
    assert "Error" in result.stdout or "not found" in result.stdout.lower()


def test_sbom_import_invalid_file(runner, tmp_path):
    """Test importing invalid SBOM file"""
    invalid_file = tmp_path / "invalid.json"
    invalid_file.write_text("not valid json")
    
    result = runner.invoke(app, ["import-sbom", str(invalid_file)])
    
    # Should handle error gracefully
    assert result.exit_code != 0 or "Error" in result.stdout

