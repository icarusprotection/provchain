"""Tests for OSV.dev integration"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from provchain.data.cache import Cache
from provchain.data.db import Database
from provchain.data.models import PackageIdentifier
from provchain.integrations.osv import OSVClient


@pytest.fixture
def osv_client():
    """Create OSV client for testing"""
    db = Database(":memory:")
    cache = Cache(db)
    return OSVClient(cache=cache)


def test_osv_client_init(osv_client):
    """Test OSV client initialization"""
    assert osv_client is not None
    assert osv_client.cache is not None


def test_osv_client_query_by_package_mock(osv_client):
    """Test querying vulnerabilities by package (mocked)"""
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "vulns": [
            {
                "id": "GHSA-xxxx-xxxx-xxxx",
                "summary": "Test vulnerability",
                "details": "Test details",
                "published": "2023-01-01T00:00:00Z",
                "references": [{"url": "https://example.com"}],
                "affected": [
                    {
                        "package": {"name": "test-package", "ecosystem": "PyPI"},
                        "ranges": [
                            {
                                "events": [
                                    {"introduced": "1.0.0"},
                                    {"fixed": "1.0.1"},
                                ]
                            }
                        ],
                    }
                ],
            }
        ]
    }

    with patch.object(osv_client.client, "post", return_value=mock_response):
        result = osv_client.query_by_package("test-package", "1.0.0")
        assert len(result) == 1
        assert result[0]["id"] == "GHSA-xxxx-xxxx-xxxx"


def test_osv_client_parse_vulnerability(osv_client):
    """Test parsing vulnerability data"""
    vuln_data = {
        "id": "GHSA-xxxx-xxxx-xxxx",
        "summary": "Test vulnerability",
        "details": "Test details",
        "published": "2023-01-01T00:00:00Z",
        "modified": "2023-01-02T00:00:00Z",
        "references": [{"url": "https://example.com"}],
        "affected": [
            {
                "package": {"name": "test-package", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "events": [
                            {"introduced": "1.0.0"},
                            {"fixed": "1.0.1"},
                        ]
                    }
                ],
            }
        ],
    }

    package = PackageIdentifier(ecosystem="pypi", name="test-package", version="1.0.0")
    vuln = osv_client.parse_vulnerability(vuln_data, package)

    assert vuln.id == "GHSA-xxxx-xxxx-xxxx"
    assert vuln.summary == "Test vulnerability"
    assert "1.0.1" in vuln.fixed_versions
    assert vuln.patch_available is True


def test_osv_client_get_vulnerabilities_for_package_mock(osv_client):
    """Test getting vulnerabilities for a package (mocked)"""
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "vulns": [
            {
                "id": "GHSA-xxxx-xxxx-xxxx",
                "summary": "Test vulnerability",
                "details": "Test details",
                "published": "2023-01-01T00:00:00Z",
                "references": [{"url": "https://example.com"}],
                "affected": [
                    {
                        "package": {"name": "test-package", "ecosystem": "PyPI"},
                        "ranges": [
                            {
                                "events": [
                                    {"introduced": "1.0.0"},
                                    {"fixed": "1.0.1"},
                                ]
                            }
                        ],
                    }
                ],
            }
        ]
    }

    package = PackageIdentifier(ecosystem="pypi", name="test-package", version="1.0.0")

    with patch.object(osv_client.client, "post", return_value=mock_response):
        vulnerabilities = osv_client.get_vulnerabilities_for_package(package)
        assert len(vulnerabilities) == 1
        assert vulnerabilities[0].id == "GHSA-xxxx-xxxx-xxxx"

