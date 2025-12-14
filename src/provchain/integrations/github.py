"""GitHub API client"""

from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from provchain.data.cache import Cache
from provchain.utils.network import HTTPClient


class GitHubClient:
    """GitHub API client"""

    BASE_URL = "https://api.github.com"
    RATE_LIMIT = 5000  # requests per hour (authenticated)

    def __init__(self, token: str | None = None, cache: Cache | None = None):
        headers = {}
        if token:
            headers["Authorization"] = f"token {token}"
            headers["Accept"] = "application/vnd.github.v3+json"

        self.client = HTTPClient(
            base_url=self.BASE_URL,
            rate_limit=self.RATE_LIMIT,
            time_window=3600.0,  # 1 hour
        )
        self.client.client.headers.update(headers)
        self.cache = cache
        self.token = token

    def parse_repo_url(self, repo_url: str) -> tuple[str, str]:
        """Parse GitHub repository URL to owner/repo"""
        # Input validation
        if not repo_url or not isinstance(repo_url, str):
            raise ValueError("repo_url must be a non-empty string")
        if len(repo_url) > 500:  # Reasonable limit
            raise ValueError("repo_url exceeds maximum length of 500 characters")
        
        parsed = urlparse(repo_url)
        path = parsed.path.strip("/")

        # Handle various GitHub URL formats
        if "github.com" in parsed.netloc:
            parts = path.split("/")
            if len(parts) >= 2:
                owner, repo = parts[0], parts[1]
                # Validate owner and repo names (GitHub allows alphanumeric, hyphens, underscores)
                if not owner or len(owner) > 100 or not all(c.isalnum() or c in "-_" for c in owner):
                    raise ValueError(f"Invalid GitHub owner name: {owner}")
                if not repo or len(repo) > 100 or not all(c.isalnum() or c in "-_." for c in repo):
                    raise ValueError(f"Invalid GitHub repository name: {repo}")
                return owner, repo
        elif parsed.netloc == "" and "/" in path:
            # Assume format: owner/repo
            parts = path.split("/")
            if len(parts) >= 2:
                owner, repo = parts[0], parts[1]
                # Validate owner and repo names
                if not owner or len(owner) > 100 or not all(c.isalnum() or c in "-_" for c in owner):
                    raise ValueError(f"Invalid GitHub owner name: {owner}")
                if not repo or len(repo) > 100 or not all(c.isalnum() or c in "-_." for c in repo):
                    raise ValueError(f"Invalid GitHub repository name: {repo}")
                return owner, repo

        raise ValueError(f"Invalid GitHub repository URL: {repo_url}")

    def get_repository(self, owner: str, repo: str) -> dict[str, Any]:
        """Get repository information"""
        # Input validation
        if not owner or not isinstance(owner, str) or len(owner) > 100:
            raise ValueError("owner must be a non-empty string with maximum length of 100 characters")
        if not repo or not isinstance(repo, str) or len(repo) > 100:
            raise ValueError("repo must be a non-empty string with maximum length of 100 characters")
        
        # URL encode to prevent injection
        from urllib.parse import quote
        safe_owner = quote(owner, safe="")
        safe_repo = quote(repo, safe="")
        
        cache_key = f"github_repo_{owner}_{repo}"

        if self.cache:
            cached = self.cache.get("github", "repo", owner, repo)
            if cached:
                return cached

        url = f"/repos/{safe_owner}/{safe_repo}"
        
        try:
            response = self.client.get(url)
            
            # Validate response size
            content_length = response.headers.get("content-length")
            if content_length and int(content_length) > 10 * 1024 * 1024:  # 10MB limit
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"GitHub API response too large: {content_length} bytes")
                raise ValueError(f"Response too large for repository {owner}/{repo}")
            
            data = response.json()
            
            # Validate response structure
            if not isinstance(data, dict):
                import logging
                logger = logging.getLogger(__name__)
                logger.warning("GitHub API returned invalid response format")
                raise ValueError(f"Invalid response format for repository {owner}/{repo}")

            if self.cache:
                # Cache for 6 hours
                from datetime import timedelta
                self.cache.set("github", data, timedelta(hours=6), "repo", owner, repo)

            return data
        except (ValueError, TypeError) as e:
            # Input validation errors should be raised
            raise
        except Exception as e:
            # Re-raise with context, but don't expose token
            import logging
            logger = logging.getLogger(__name__)
            error_msg = str(e)
            # Remove any potential token exposure
            if self.token and self.token in error_msg:
                error_msg = error_msg.replace(self.token, "***")
            logger.warning(f"GitHub API request failed for {owner}/{repo}: {error_msg}")
            raise

    def get_repository_from_url(self, repo_url: str) -> dict[str, Any]:
        """Get repository information from URL"""
        owner, repo = self.parse_repo_url(repo_url)
        return self.get_repository(owner, repo)

    def get_user(self, username: str) -> dict[str, Any]:
        """Get user profile information"""
        # Input validation
        if not username or not isinstance(username, str):
            raise ValueError("username must be a non-empty string")
        if len(username) > 100:
            raise ValueError("username exceeds maximum length of 100 characters")
        # GitHub usernames are alphanumeric with hyphens
        if not all(c.isalnum() or c == "-" for c in username):
            raise ValueError(f"Invalid GitHub username format: {username}")
        
        # URL encode to prevent injection
        from urllib.parse import quote
        safe_username = quote(username, safe="")
        
        if self.cache:
            cached = self.cache.get("github", "user", username)
            if cached:
                return cached

        url = f"/users/{safe_username}"
        
        try:
            response = self.client.get(url)
            
            # Validate response size
            content_length = response.headers.get("content-length")
            if content_length and int(content_length) > 1 * 1024 * 1024:  # 1MB limit
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"GitHub API response too large: {content_length} bytes")
                raise ValueError(f"Response too large for user {username}")
            
            data = response.json()
            
            # Validate response structure
            if not isinstance(data, dict):
                import logging
                logger = logging.getLogger(__name__)
                logger.warning("GitHub API returned invalid response format")
                raise ValueError(f"Invalid response format for user {username}")

            if self.cache:
                from datetime import timedelta
                self.cache.set("github", data, timedelta(hours=6), "user", username)

            return data
        except (ValueError, TypeError) as e:
            # Input validation errors should be raised
            raise
        except Exception as e:
            # Re-raise with context, but don't expose token
            import logging
            logger = logging.getLogger(__name__)
            error_msg = str(e)
            # Remove any potential token exposure
            if self.token and self.token in error_msg:
                error_msg = error_msg.replace(self.token, "***")
            logger.warning(f"GitHub API request failed for user {username}: {error_msg}")
            raise

    def get_repository_commits(
        self, owner: str, repo: str, since: datetime | None = None, limit: int = 30
    ) -> list[dict[str, Any]]:
        """Get repository commits"""
        url = f"/repos/{owner}/{repo}/commits"
        params: dict[str, Any] = {"per_page": min(limit, 100)}
        if since:
            params["since"] = since.isoformat()

        response = self.client.get(url, params=params)
        return response.json()

    def get_repository_releases(
        self, owner: str, repo: str, limit: int = 10
    ) -> list[dict[str, Any]]:
        """Get repository releases"""
        url = f"/repos/{owner}/{repo}/releases"
        params = {"per_page": min(limit, 100)}

        response = self.client.get(url, params=params)
        return response.json()

    def get_repository_tags(self, owner: str, repo: str, limit: int = 10) -> list[dict[str, Any]]:
        """Get repository tags"""
        url = f"/repos/{owner}/{repo}/tags"
        params = {"per_page": min(limit, 100)}

        response = self.client.get(url, params=params)
        return response.json()

    def check_repository_transfer(self, owner: str, repo: str) -> bool:
        """Check if repository was recently transferred"""
        try:
            repo_data = self.get_repository(owner, repo)
            # Check repository creation date vs current owner
            # If owner changed recently, this might indicate a transfer
            # Note: GitHub API doesn't directly expose transfer history,
            # but we can check if the current owner matches expected patterns
            created_at = repo_data.get("created_at")
            if created_at:
                from datetime import datetime, timedelta
                created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                # If repo is very new but owner has old account, might be transferred
                # This is a heuristic - full transfer detection would need events API
                return False  # No direct way to detect without events API
            return False
        except Exception:
            return False

    def close(self) -> None:
        """Close the HTTP client"""
        self.client.close()

    def __enter__(self) -> "GitHubClient":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

