"""GitLab API client"""

from typing import Any

from provchain.data.cache import Cache
from provchain.utils.network import HTTPClient


class GitLabClient:
    """GitLab API client (basic implementation)"""

    def __init__(self, base_url: str = "https://gitlab.com", token: str | None = None, cache: Cache | None = None):
        headers = {}
        if token:
            headers["PRIVATE-TOKEN"] = token

        self.client = HTTPClient(
            base_url=f"{base_url}/api/v4",
            rate_limit=100,
            time_window=60.0,
        )
        self.client.client.headers.update(headers)
        self.cache = cache
        self.token = token

    def get_project(self, project_path: str) -> dict[str, Any]:
        """Get project information"""
        if self.cache:
            cached = self.cache.get("gitlab", "project", project_path)
            if cached:
                return cached

        url = f"/projects/{project_path.replace('/', '%2F')}"
        response = self.client.get(url)
        data = response.json()

        if self.cache:
            from datetime import timedelta
            self.cache.set("gitlab", data, timedelta(hours=6), "project", project_path)

        return data

    def close(self) -> None:
        """Close the HTTP client"""
        self.client.close()

    def __enter__(self) -> "GitLabClient":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

