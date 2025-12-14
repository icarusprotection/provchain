"""Tests for GitLab integration"""

import pytest
from unittest.mock import Mock, patch

from provchain.integrations.gitlab import GitLabClient
from provchain.data.cache import Cache


@pytest.fixture
def gitlab_client(cache):
    """Create GitLab client with cache"""
    return GitLabClient(token="test-token", cache=cache)


def test_get_project(gitlab_client):
    """Test getting project information"""
    with patch.object(gitlab_client.client, 'get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = {
            "name": "test-project",
            "path": "test-project",
        }
        mock_get.return_value = mock_response
        
        project = gitlab_client.get_project("owner/test-project")
        
        assert project["name"] == "test-project"
        mock_get.assert_called_once()


def test_gitlab_client_with_token():
    """Test GitLab client with authentication token"""
    client = GitLabClient(token="test-token")
    
    # Should have private token header
    assert "PRIVATE-TOKEN" in client.client.client.headers
    assert client.client.client.headers["PRIVATE-TOKEN"] == "test-token"


def test_gitlab_client_without_token():
    """Test GitLab client without token"""
    client = GitLabClient()
    
    # Should not have private token header
    assert "PRIVATE-TOKEN" not in client.client.client.headers or \
           client.client.client.headers.get("PRIVATE-TOKEN") is None


def test_gitlab_client_context_manager(gitlab_client):
    """Test GitLab client as context manager"""
    # Mock the close method
    gitlab_client.client.close = Mock()
    
    with gitlab_client as client:
        assert client is gitlab_client
    
    # Should close after context
    gitlab_client.client.close.assert_called_once()


def test_get_project_with_cache(gitlab_client):
    """Test getting project with cache - covers line 31"""
    cached_data = {
        "name": "cached-project",
        "path": "cached-project",
    }
    
    with patch.object(gitlab_client.cache, 'get', return_value=cached_data), \
         patch.object(gitlab_client.client, 'get') as mock_get:
        project = gitlab_client.get_project("owner/test-project")
        
        assert project == cached_data
        # Should not call API when cached (line 31)
        mock_get.assert_not_called()

