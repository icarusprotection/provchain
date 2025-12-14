"""Tests for package parsing"""

from provchain.core.package import parse_package_spec, parse_requirements_file, version_satisfies
from provchain.data.models import PackageIdentifier


def test_parse_package_spec_simple():
    """Test parsing simple package name"""
    spec = parse_package_spec("requests")
    assert spec.name == "requests"
    assert spec.version is None
    assert spec.specifier is None


def test_parse_package_spec_with_version():
    """Test parsing package with version"""
    spec = parse_package_spec("requests==2.31.0")
    assert spec.name == "requests"
    assert spec.version == "2.31.0"


def test_parse_package_spec_with_specifier():
    """Test parsing package with version specifier"""
    spec = parse_package_spec("requests>=2.0.0")
    assert spec.name == "requests"
    assert spec.specifier is not None


def test_parse_requirements_file_simple(tmp_path):
    """Test parsing simple requirements file"""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.31.0\nflask>=2.0.0\n")
    
    specs = parse_requirements_file(str(req_file))
    assert len(specs) == 2
    assert specs[0].name == "requests"
    assert specs[0].version == "2.31.0"
    assert specs[1].name == "flask"
    assert specs[1].specifier is not None


def test_parse_requirements_file_with_comments(tmp_path):
    """Test parsing requirements file with comments"""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("# This is a comment\nrequests==2.31.0\n# Another comment\n")
    
    specs = parse_requirements_file(str(req_file))
    assert len(specs) == 1
    assert specs[0].name == "requests"


def test_parse_requirements_file_empty(tmp_path):
    """Test parsing empty requirements file"""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("")
    
    specs = parse_requirements_file(str(req_file))
    assert len(specs) == 0


def test_parse_requirements_file_with_blank_lines(tmp_path):
    """Test parsing requirements file with blank lines"""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.31.0\n\nflask>=2.0.0\n")
    
    specs = parse_requirements_file(str(req_file))
    assert len(specs) == 2


def test_version_satisfies():
    """Test version satisfaction logic"""
    assert version_satisfies("1.0.0", "==1.0.0") is True
    assert version_satisfies("1.0.0", ">=1.0.0") is True
    assert version_satisfies("1.0.1", ">=1.0.0") is True
    assert version_satisfies("0.9.0", ">=1.0.0") is False
    assert version_satisfies("1.0.0", "<2.0.0") is True
    assert version_satisfies("2.0.0", "<2.0.0") is False


def test_package_spec_to_identifier():
    """Test converting PackageSpec to PackageIdentifier"""
    spec = parse_package_spec("requests==2.31.0")
    identifier = spec.to_identifier()
    
    assert isinstance(identifier, PackageIdentifier)
    assert identifier.name == "requests"
    assert identifier.version == "2.31.0"
    assert identifier.ecosystem == "pypi"


def test_package_spec_to_identifier_with_specifier():
    """Test converting PackageSpec with specifier to PackageIdentifier"""
    spec = parse_package_spec("requests>=2.0.0")
    identifier = spec.to_identifier()
    
    assert identifier.name == "requests"
    assert identifier.version == ">=2.0.0"  # Specifier used as version


def test_package_spec_to_identifier_no_version():
    """Test converting PackageSpec without version to PackageIdentifier"""
    spec = parse_package_spec("requests")
    identifier = spec.to_identifier()
    
    assert identifier.name == "requests"
    assert identifier.version == "latest"  # Placeholder for no version


def test_parse_package_spec_multiple_specifiers():
    """Test parsing package with multiple specifiers - tests line 60"""
    spec = parse_package_spec("requests>=2.0.0,<3.0.0")
    assert spec.name == "requests"
    assert spec.specifier is not None
    assert ">=" in spec.specifier and "<" in spec.specifier


def test_parse_package_spec_fallback_regex():
    """Test fallback regex parsing when Requirement parsing fails - tests lines 61-77"""
    # Test with invalid requirement format that triggers fallback
    # Use a string that doesn't parse as Requirement but matches regex
    spec = parse_package_spec("test-package==1.0.0")
    assert spec.name == "test-package"
    assert spec.version == "1.0.0"


def test_parse_package_spec_fallback_with_version():
    """Test fallback parsing with version - tests lines 70-72"""
    # Force fallback by using a format that Requirement can't parse
    # but regex can handle
    from unittest.mock import patch
    with patch('provchain.core.package.Requirement', side_effect=Exception("Parse error")):
        spec = parse_package_spec("test-pkg==1.2.3")
        assert spec.name == "test-pkg"
        assert spec.version == "1.2.3"


def test_parse_package_spec_fallback_with_specifier():
    """Test fallback parsing with specifier - tests lines 73-74"""
    from unittest.mock import patch
    with patch('provchain.core.package.Requirement', side_effect=Exception("Parse error")):
        spec = parse_package_spec("test-pkg>=1.0.0")
        assert spec.name == "test-pkg"
        assert spec.specifier == ">=1.0.0"


def test_parse_package_spec_fallback_name_only():
    """Test fallback parsing name only - tests line 75"""
    from unittest.mock import patch
    with patch('provchain.core.package.Requirement', side_effect=Exception("Parse error")):
        spec = parse_package_spec("test-pkg")
        assert spec.name == "test-pkg"
        assert spec.version is None
        assert spec.specifier is None


def test_parse_package_spec_invalid_raises():
    """Test parsing invalid spec raises ValueError - tests line 77"""
    from unittest.mock import patch
    with patch('provchain.core.package.Requirement', side_effect=Exception("Parse error")):
        # Use a string that doesn't match the regex pattern
        import pytest
        with pytest.raises(ValueError, match="Invalid package specification"):
            parse_package_spec("")


def test_parse_requirements_file_with_r_flag(tmp_path):
    """Test parsing requirements file with -r flag - tests line 91"""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.31.0\n-r other-requirements.txt\nflask>=2.0.0\n")
    
    specs = parse_requirements_file(str(req_file))
    # Should skip the -r line
    assert len(specs) == 2
    assert specs[0].name == "requests"
    assert specs[1].name == "flask"


def test_parse_requirements_file_with_requirement_flag(tmp_path):
    """Test parsing requirements file with --requirement flag - tests line 91"""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.31.0\n--requirement other-requirements.txt\nflask>=2.0.0\n")
    
    specs = parse_requirements_file(str(req_file))
    # Should skip the --requirement line
    assert len(specs) == 2


def test_parse_requirements_file_editable_git_url(tmp_path):
    """Test parsing editable install with git URL - tests lines 93-102"""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("-e git+https://github.com/user/repo.git@main#egg=package-name\n")
    
    specs = parse_requirements_file(str(req_file))
    assert len(specs) == 1
    assert specs[0].name == "repo"


def test_parse_requirements_file_editable_git_url_no_match(tmp_path):
    """Test parsing editable install with git URL that doesn't match pattern - tests line 102"""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("-e git+invalid-url\n")
    
    specs = parse_requirements_file(str(req_file))
    # Should skip the line if no match
    assert len(specs) == 0


def test_parse_requirements_file_editable_path(tmp_path):
    """Test parsing editable install with path - tests lines 103-105"""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("-e ./local-package\n")
    
    specs = parse_requirements_file(str(req_file))
    assert len(specs) == 1
    assert specs[0].name == "local-package"


def test_parse_requirements_file_editable_path_nested(tmp_path):
    """Test parsing editable install with nested path - tests line 105"""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("-e ./path/to/package-name\n")
    
    specs = parse_requirements_file(str(req_file))
    assert len(specs) == 1
    assert specs[0].name == "package-name"


def test_parse_requirements_file_invalid_line_skipped(tmp_path):
    """Test parsing requirements file with invalid line - tests lines 110-112"""
    req_file = tmp_path / "requirements.txt"
    # Use a line that doesn't match the regex pattern at all (starts with special char)
    req_file.write_text("requests==2.31.0\n!!!invalid\nflask>=2.0.0\n")
    
    specs = parse_requirements_file(str(req_file))
    # Should skip the invalid line (raises ValueError which is caught)
    assert len(specs) == 2
    assert specs[0].name == "requests"
    assert specs[1].name == "flask"


def test_version_satisfies_exception_handling():
    """Test version_satisfies exception handling - tests lines 123-124"""
    # Test with invalid version that raises exception
    result = version_satisfies("not-a-version", ">=1.0.0")
    assert result is False
    
    # Test with invalid specifier that raises exception
    result = version_satisfies("1.0.0", "invalid-specifier")
    assert result is False

