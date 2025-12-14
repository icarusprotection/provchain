"""Tests for GitHub integration"""

import pytest
from unittest.mock import Mock, patch

from provchain.integrations.github import GitHubClient
from provchain.data.cache import Cache
from provchain.data.db import Database


@pytest.fixture
def github_client(cache):
    """Create GitHub client with cache"""
    return GitHubClient(token="test-token", cache=cache)


def test_parse_repo_url():
    """Test parsing GitHub repository URLs"""
    client = GitHubClient()
    
    owner, repo = client.parse_repo_url("https://github.com/owner/repo")
    assert owner == "owner"
    assert repo == "repo"
    
    owner, repo = client.parse_repo_url("owner/repo")
    assert owner == "owner"
    assert repo == "repo"


def test_parse_repo_url_invalid():
    """Test parsing invalid repository URL"""
    client = GitHubClient()
    
    with pytest.raises(ValueError):
        client.parse_repo_url("invalid-url")


def test_get_repository(github_client):
    """Test getting repository information"""
    with patch.object(github_client.client, 'get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = {
            "name": "test-repo",
            "full_name": "owner/test-repo",
            "description": "Test repository",
        }
        mock_get.return_value = mock_response
        
        repo = github_client.get_repository("owner", "test-repo")
        
        assert repo["name"] == "test-repo"
        mock_get.assert_called_once()


def test_get_user(github_client):
    """Test getting user information"""
    with patch.object(github_client.client, 'get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = {
            "login": "testuser",
            "created_at": "2020-01-01T00:00:00Z",
            "followers": 10,
        }
        mock_get.return_value = mock_response
        
        user = github_client.get_user("testuser")
        
        assert user["login"] == "testuser"
        mock_get.assert_called_once()


def test_github_client_with_token():
    """Test GitHub client with authentication token"""
    client = GitHubClient(token="test-token")
    
    # Should have authorization header
    assert "Authorization" in client.client.client.headers
    assert "token test-token" in client.client.client.headers["Authorization"]


def test_github_client_without_token():
    """Test GitHub client without token"""
    client = GitHubClient()
    
    # Should not have authorization header
    assert "Authorization" not in client.client.client.headers or \
           client.client.client.headers.get("Authorization") is None


def test_github_client_context_manager(github_client):
    """Test GitHub client as context manager"""
    # Mock the close method
    github_client.client.close = Mock()
    
    with github_client as client:
        assert client is github_client
    
    # Should close after context
    github_client.client.close.assert_called_once()


def test_get_repository_with_cache(github_client):
    """Test getting repository with cache - tests line 56"""
    # Set up cache to return cached value
    cached_data = {"name": "cached-repo", "full_name": "owner/cached-repo"}
    with patch.object(github_client.cache, 'get', return_value=cached_data), \
         patch.object(github_client.client, 'get') as mock_get:
        repo = github_client.get_repository("owner", "repo")
        
        assert repo == cached_data
        # Should not call API when cached
        mock_get.assert_not_called()


def test_get_repository_from_url(github_client):
    """Test getting repository from URL - tests lines 71-72"""
    with patch.object(github_client.client, 'get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = {
            "name": "test-repo",
            "full_name": "owner/test-repo",
        }
        mock_get.return_value = mock_response
        
        repo = github_client.get_repository_from_url("https://github.com/owner/test-repo")
        
        assert repo["name"] == "test-repo"
        mock_get.assert_called_once()


def test_get_user_with_cache(github_client):
    """Test getting user with cache - tests line 79"""
    # Set up cache to return cached value
    cached_data = {"login": "cached-user", "created_at": "2020-01-01T00:00:00Z"}
    with patch.object(github_client.cache, 'get', return_value=cached_data), \
         patch.object(github_client.client, 'get') as mock_get:
        user = github_client.get_user("testuser")
        
        assert user == cached_data
        # Should not call API when cached
        mock_get.assert_not_called()


def test_get_repository_commits(github_client):
    """Test getting repository commits - tests lines 95-101"""
    with patch.object(github_client.client, 'get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = [
            {"sha": "abc123", "commit": {"message": "Test commit"}},
            {"sha": "def456", "commit": {"message": "Another commit"}},
        ]
        mock_get.return_value = mock_response
        
        commits = github_client.get_repository_commits("owner", "repo", limit=2)
        
        assert len(commits) == 2
        mock_get.assert_called_once()
        # Verify params were passed
        call_args = mock_get.call_args
        assert "params" in call_args.kwargs or len(call_args[0]) > 1


def test_get_repository_commits_with_since(github_client):
    """Test getting repository commits with since parameter"""
    from datetime import datetime, timezone
    with patch.object(github_client.client, 'get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = []
        mock_get.return_value = mock_response
        
        since = datetime.now(timezone.utc)
        commits = github_client.get_repository_commits("owner", "repo", since=since, limit=10)
        
        mock_get.assert_called_once()
        # Verify since parameter was included
        call_kwargs = mock_get.call_args.kwargs
        if "params" in call_kwargs:
            assert "since" in call_kwargs["params"]


def test_get_repository_releases(github_client):
    """Test getting repository releases - tests lines 107-111"""
    with patch.object(github_client.client, 'get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = [
            {"tag_name": "v1.0.0", "name": "Release 1.0.0"},
            {"tag_name": "v2.0.0", "name": "Release 2.0.0"},
        ]
        mock_get.return_value = mock_response
        
        releases = github_client.get_repository_releases("owner", "repo", limit=5)
        
        assert len(releases) == 2
        mock_get.assert_called_once()


def test_get_repository_tags(github_client):
    """Test getting repository tags - tests lines 115-119"""
    with patch.object(github_client.client, 'get') as mock_get:
        mock_response = Mock()
        mock_response.json.return_value = [
            {"name": "v1.0.0", "commit": {"sha": "abc123"}},
            {"name": "v2.0.0", "commit": {"sha": "def456"}},
        ]
        mock_get.return_value = mock_response
        
        tags = github_client.get_repository_tags("owner", "repo", limit=5)
        
        assert len(tags) == 2
        mock_get.assert_called_once()


def test_check_repository_transfer_success(github_client):
    """Test checking repository transfer - tests lines 123-138"""
    with patch.object(github_client, 'get_repository') as mock_get_repo:
        mock_get_repo.return_value = {
            "created_at": "2023-01-01T00:00:00Z",
            "owner": {"login": "current-owner"},
        }
        
        result = github_client.check_repository_transfer("owner", "repo")
        
        # Should return False (heuristic always returns False)
        assert result is False
        mock_get_repo.assert_called_once()


def test_check_repository_transfer_no_created_at(github_client):
    """Test checking repository transfer without created_at - tests line 136"""
    with patch.object(github_client, 'get_repository') as mock_get_repo:
        mock_get_repo.return_value = {
            "owner": {"login": "current-owner"},
            # No created_at
        }
        
        result = github_client.check_repository_transfer("owner", "repo")
        
        assert result is False


def test_check_repository_transfer_exception(github_client):
    """Test checking repository transfer with exception - tests lines 137-138"""
    with patch.object(github_client, 'get_repository', side_effect=Exception("API error")):
        result = github_client.check_repository_transfer("owner", "repo")
        
        # Should return False on exception
        assert result is False

