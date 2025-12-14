"""Tests for PyPI integration"""

import pytest
from unittest.mock import Mock, patch

from provchain.data.cache import Cache
from provchain.integrations.pypi import PyPIClient
from provchain.data.db import Database


@pytest.fixture
def pypi_client(cache):
    """Create PyPI client with cache"""
    return PyPIClient(cache=cache)


def test_pypi_client_get_package_metadata(pypi_client):
    """Test getting package metadata from PyPI"""
    with patch.object(pypi_client.client, 'get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = {
            "info": {
                "name": "requests",
                "version": "2.31.0",
                "summary": "HTTP library",
                "description": "Python HTTP library",
            },
            "releases": {
                "2.31.0": []
            }
        }
        mock_get.return_value = mock_response
        
        metadata = pypi_client.get_package_metadata("requests", "2.31.0")
        
        assert metadata["info"]["name"] == "requests"
        mock_get.assert_called_once()


def test_pypi_client_get_package_metadata_latest(pypi_client):
    """Test getting latest package metadata"""
    with patch.object(pypi_client.client, 'get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = {
            "info": {
                "name": "requests",
                "version": "2.31.0",
            },
            "releases": {}
        }
        mock_get.return_value = mock_response
        
        metadata = pypi_client.get_package_metadata("requests")
        
        assert metadata["info"]["name"] == "requests"
        # Should call without version in URL
        assert any("/requests/json" in str(call) for call in mock_get.call_args_list)


def test_pypi_client_get_package_info(pypi_client):
    """Test getting package info as PackageMetadata"""
    with patch.object(pypi_client.client, 'get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = {
            "info": {
                "name": "requests",
                "version": "2.31.0",
                "summary": "HTTP library",
                "description": "Python HTTP library",
                "home_page": "https://requests.readthedocs.io",
                "project_url": "https://github.com/psf/requests",
                "license": "Apache 2.0",
                "requires_dist": ["urllib3"],
            },
            "releases": {
                "2.31.0": [{"upload_time": "2023-06-01T00:00:00"}]
            }
        }
        mock_get.return_value = mock_response
        
        package_info = pypi_client.get_package_info("requests", "2.31.0")
        
        assert package_info.identifier.name == "requests"
        assert package_info.identifier.version == "2.31.0"
        assert package_info.homepage == "https://requests.readthedocs.io"


def test_pypi_client_caching(pypi_client):
    """Test that PyPI client uses cache"""
    with patch.object(pypi_client.client, 'get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = {"info": {"name": "requests"}}
        mock_get.return_value = mock_response
        
        # First call
        pypi_client.get_package_metadata("requests")
        assert mock_get.call_count == 1
        
        # Second call should use cache
        pypi_client.get_package_metadata("requests")
        assert mock_get.call_count == 1  # Still 1, used cache


def test_pypi_client_get_version_list(pypi_client):
    """Test getting version list"""
    with patch.object(pypi_client.client, 'get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = {
            "releases": {
                "1.0.0": [],
                "2.0.0": [],
                "2.31.0": [],
            }
        }
        mock_get.return_value = mock_response
        
        versions = pypi_client.get_version_list("requests")
        
        assert "2.31.0" in versions
        assert "2.0.0" in versions
        assert "1.0.0" in versions
        # Should be sorted reverse
        assert versions[0] == "2.31.0"


def test_pypi_client_context_manager(pypi_client):
    """Test PyPI client as context manager"""
    # Mock the close method
    pypi_client.client.close = Mock()
    
    with pypi_client as client:
        assert client is pypi_client
    
    # Should close after context
    pypi_client.client.close.assert_called_once()


def test_pypi_client_close():
    """Test closing PyPI client"""
    client = PyPIClient()
    # Mock the close method
    client.client.close = Mock()
    client.close()
    client.client.close.assert_called_once()


def test_pypi_client_get_package_info_version_not_found(pypi_client):
    """Test getting package info with version not found - tests lines 59-62"""
    with patch.object(pypi_client.client, 'get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = {
            "info": {"name": "requests", "version": "2.31.0"},
            "releases": {
                "2.31.0": [],
                # Requested version "1.0.0" not in releases
            }
        }
        mock_get.return_value = mock_response
        
        import pytest
        with pytest.raises(ValueError, match="Version 1.0.0 not found"):
            pypi_client.get_package_info("requests", "1.0.0")


def test_pypi_client_get_package_info_no_version(pypi_client):
    """Test getting package info without version - tests line 69"""
    with patch.object(pypi_client.client, 'get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = {
            "info": {
                "name": "requests",
                "version": "2.31.0",
                "author": "Test Author",
                "author_email": "test@example.com",
            },
            "releases": {
                "2.31.0": [{"upload_time": "2023-06-01T00:00:00Z"}]
            }
        }
        mock_get.return_value = mock_response
        
        package_info = pypi_client.get_package_info("requests")
        
        assert package_info.identifier.version == "2.31.0"
        assert len(package_info.maintainers) == 1


def test_pypi_client_get_package_info_release_date_parsing_error(pypi_client):
    """Test package info with release date parsing error - tests lines 85-86"""
    with patch.object(pypi_client.client, 'get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = {
            "info": {
                "name": "requests",
                "version": "2.31.0",
            },
            "releases": {
                "2.31.0": [{"upload_time": "invalid-date-format"}]
            }
        }
        mock_get.return_value = mock_response
        
        package_info = pypi_client.get_package_info("requests", "2.31.0")
        
        # Should handle parsing error gracefully
        assert package_info.identifier.name == "requests"


def test_pypi_client_get_package_info_no_upload_time(pypi_client):
    """Test package info with releases but no upload_time"""
    with patch.object(pypi_client.client, 'get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = {
            "info": {"name": "requests", "version": "2.31.0"},
            "releases": {
                "2.31.0": [{}]  # No upload_time
            }
        }
        mock_get.return_value = mock_response
        
        package_info = pypi_client.get_package_info("requests", "2.31.0")
        
        assert package_info.identifier.name == "requests"
        assert package_info.first_release is None


def test_pypi_client_search_packages(pypi_client):
    """Test searching packages - tests lines 118-121"""
    results = pypi_client.search_packages("requests", limit=10)
    
    # Currently returns empty list (simplified implementation)
    assert results == []

