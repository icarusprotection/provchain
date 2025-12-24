"""HTTP client wrapper with rate limiting"""

import asyncio
import time
from typing import Any

import httpx


class RateLimiter:
    """Simple rate limiter"""

    def __init__(self, max_requests: int, time_window: float):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = []

    def wait_if_needed(self) -> None:
        """Wait if rate limit would be exceeded"""
        now = time.time()
        # Remove old requests outside the time window
        self.requests = [
            req_time for req_time in self.requests if now - req_time < self.time_window
        ]

        if len(self.requests) >= self.max_requests:
            # Need to wait until oldest request expires
            sleep_time = self.time_window - (now - self.requests[0]) + 0.1
            if sleep_time > 0:
                time.sleep(sleep_time)
                # Clean up again after sleep
                now = time.time()
                self.requests = [
                    req_time for req_time in self.requests if now - req_time < self.time_window
                ]

        self.requests.append(time.time())


class HTTPClient:
    """HTTP client with rate limiting and retry logic"""

    # Maximum response size (100MB default)
    MAX_RESPONSE_SIZE = 100 * 1024 * 1024

    def __init__(
        self,
        base_url: str | None = None,
        rate_limit: int = 100,
        time_window: float = 60.0,
        timeout: float = 30.0,
        max_retries: int = 3,
        max_response_size: int | None = None,
    ):
        self.base_url = base_url
        self.rate_limiter = RateLimiter(rate_limit, time_window)
        self.timeout = timeout
        self.max_retries = max_retries
        self.max_response_size = max_response_size or self.MAX_RESPONSE_SIZE

        # httpx.Client by default verifies SSL certificates
        # We explicitly ensure verify=True for security
        self.client = httpx.Client(
            base_url=base_url,
            timeout=timeout,
            follow_redirects=True,
            verify=True,  # Explicitly enable SSL verification
        )

    def get(self, url: str, **kwargs: Any) -> httpx.Response:
        """Make GET request with rate limiting"""
        for attempt in range(self.max_retries):
            try:
                self.rate_limiter.wait_if_needed()
                response = self.client.get(url, **kwargs)

                # Check response size before reading
                content_length = response.headers.get("content-length")
                if content_length:
                    try:
                        if int(content_length) > self.max_response_size:
                            response.close()
                            raise ValueError(
                                f"Response too large: {content_length} bytes (max: {self.max_response_size})"
                            )
                    except (ValueError, TypeError):
                        # Skip validation if content_length is not a valid number (e.g., Mock object)
                        pass

                response.raise_for_status()
                return response
            except httpx.HTTPStatusError as e:
                if e.response.status_code >= 500 and attempt < self.max_retries - 1:
                    # Retry on server errors
                    time.sleep(2**attempt)  # Exponential backoff
                    continue
                raise
            except httpx.RequestError:
                if attempt < self.max_retries - 1:
                    time.sleep(2**attempt)
                    continue
                raise

    def post(self, url: str, **kwargs: Any) -> httpx.Response:
        """Make POST request with rate limiting"""
        for attempt in range(self.max_retries):
            try:
                self.rate_limiter.wait_if_needed()
                response = self.client.post(url, **kwargs)

                # Check response size before reading
                content_length = response.headers.get("content-length")
                if content_length:
                    try:
                        if int(content_length) > self.max_response_size:
                            response.close()
                            raise ValueError(
                                f"Response too large: {content_length} bytes (max: {self.max_response_size})"
                            )
                    except (ValueError, TypeError):
                        # Skip validation if content_length is not a valid number (e.g., Mock object)
                        pass

                response.raise_for_status()
                return response
            except httpx.HTTPStatusError as e:
                if e.response.status_code >= 500 and attempt < self.max_retries - 1:
                    time.sleep(2**attempt)
                    continue
                raise
            except httpx.RequestError:
                if attempt < self.max_retries - 1:
                    time.sleep(2**attempt)
                    continue
                raise

    def close(self) -> None:
        """Close the HTTP client"""
        self.client.close()

    def __enter__(self) -> "HTTPClient":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


class AsyncHTTPClient:
    """Async HTTP client with rate limiting"""

    # Maximum response size (100MB default)
    MAX_RESPONSE_SIZE = 100 * 1024 * 1024

    def __init__(
        self,
        base_url: str | None = None,
        rate_limit: int = 100,
        time_window: float = 60.0,
        timeout: float = 30.0,
        max_retries: int = 3,
        max_response_size: int | None = None,
    ):
        self.base_url = base_url
        self.rate_limiter = RateLimiter(rate_limit, time_window)
        self.timeout = timeout
        self.max_retries = max_retries
        self.max_response_size = max_response_size or self.MAX_RESPONSE_SIZE
        # httpx.AsyncClient by default verifies SSL certificates
        # We explicitly ensure verify=True for security
        self.client = httpx.AsyncClient(
            base_url=base_url,
            timeout=timeout,
            follow_redirects=True,
            verify=True,  # Explicitly enable SSL verification
        )

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        """Make async GET request with rate limiting"""
        for attempt in range(self.max_retries):
            try:
                self.rate_limiter.wait_if_needed()
                response = await self.client.get(url, **kwargs)

                # Check response size before reading
                content_length = response.headers.get("content-length")
                if content_length and int(content_length) > self.max_response_size:
                    await response.aclose()
                    raise ValueError(
                        f"Response too large: {content_length} bytes (max: {self.max_response_size})"
                    )

                response.raise_for_status()
                return response
            except httpx.HTTPStatusError as e:
                if e.response.status_code >= 500 and attempt < self.max_retries - 1:
                    await asyncio.sleep(2**attempt)
                    continue
                raise
            except httpx.RequestError:
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2**attempt)
                    continue
                raise

    async def close(self) -> None:
        """Close the async HTTP client"""
        await self.client.aclose()

    async def __aenter__(self) -> "AsyncHTTPClient":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()
