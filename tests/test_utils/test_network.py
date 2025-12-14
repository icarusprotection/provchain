"""Tests for network utilities"""

import pytest
import time
from unittest.mock import Mock, patch, MagicMock, AsyncMock
import httpx

from provchain.utils.network import RateLimiter, HTTPClient, AsyncHTTPClient


class TestRateLimiter:
    """Test cases for RateLimiter"""

    def test_rate_limiter_init(self):
        """Test rate limiter initialization"""
        limiter = RateLimiter(max_requests=10, time_window=60.0)
        
        assert limiter.max_requests == 10
        assert limiter.time_window == 60.0
        assert len(limiter.requests) == 0

    def test_rate_limiter_wait_if_needed_no_wait(self):
        """Test rate limiter when no wait is needed"""
        limiter = RateLimiter(max_requests=10, time_window=60.0)
        
        # Add requests up to limit
        for _ in range(5):
            limiter.wait_if_needed()
        
        assert len(limiter.requests) == 5

    @patch('provchain.utils.network.time.sleep')
    @patch('provchain.utils.network.time.time')
    def test_rate_limiter_wait_if_needed_waits(self, mock_time, mock_sleep):
        """Test rate limiter waits when limit is reached"""
        limiter = RateLimiter(max_requests=2, time_window=60.0)
        
        # Set up time mocks
        current_time = 100.0
        mock_time.return_value = current_time
        
        # Fill up the limiter
        limiter.requests = [50.0, 60.0]  # Both within window
        
        limiter.wait_if_needed()
        
        # Should have called sleep
        mock_sleep.assert_called_once()

    @patch('provchain.utils.network.time.time')
    def test_rate_limiter_removes_old_requests(self, mock_time):
        """Test rate limiter removes old requests outside window"""
        limiter = RateLimiter(max_requests=10, time_window=60.0)
        
        current_time = 200.0  # Much later
        mock_time.return_value = current_time
        
        # Add old requests (outside window - more than 60 seconds ago)
        limiter.requests = [100.0, 110.0]  # Both > 60 seconds ago (200 - 100 = 100 > 60)
        
        limiter.wait_if_needed()
        
        # Old requests should be removed, only new one added
        assert len(limiter.requests) == 1  # Only the new one


class TestHTTPClient:
    """Test cases for HTTPClient"""

    def test_http_client_init_default(self):
        """Test HTTP client initialization with defaults"""
        with patch('provchain.utils.network.httpx.Client') as mock_client:
            client = HTTPClient()
            
            assert client.base_url is None
            assert client.timeout == 30.0
            assert client.max_retries == 3
            # Verify httpx.Client was called (may need to handle None base_url)
            mock_client.assert_called_once()

    def test_http_client_init_custom(self):
        """Test HTTP client initialization with custom parameters"""
        client = HTTPClient(
            base_url="https://api.example.com",
            rate_limit=50,
            time_window=30.0,
            timeout=60.0,
            max_retries=5
        )
        
        assert client.base_url == "https://api.example.com"
        assert client.timeout == 60.0
        assert client.max_retries == 5

    def test_http_client_get_success(self):
        """Test successful GET request"""
        with patch('provchain.utils.network.httpx.Client') as mock_client_class:
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"data": "test"}
            mock_response.raise_for_status = Mock()
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client
            
            client = HTTPClient(base_url="https://api.example.com")
            response = client.get("/test")
            
            assert response.status_code == 200
            mock_response.raise_for_status.assert_called_once()

    def test_http_client_get_with_retry(self):
        """Test GET request with retry on server error"""
        with patch('provchain.utils.network.httpx.Client') as mock_client_class:
            mock_client = MagicMock()
            mock_response_500 = MagicMock()
            mock_response_500.status_code = 500
            mock_response_500.raise_for_status.side_effect = httpx.HTTPStatusError(
                "Server Error", request=Mock(), response=mock_response_500
            )
            
            mock_response_200 = MagicMock()
            mock_response_200.status_code = 200
            mock_response_200.raise_for_status = Mock()
            
            mock_client.get.side_effect = [mock_response_500, mock_response_200]
            mock_client_class.return_value = mock_client
            
            with patch('provchain.utils.network.time.sleep'):
                client = HTTPClient(base_url="https://api.example.com", max_retries=3)
                response = client.get("/test")
                
                assert response.status_code == 200

    def test_http_client_get_request_error_retry(self):
        """Test GET request with retry on RequestError"""
        with patch('provchain.utils.network.httpx.Client') as mock_client_class:
            mock_client = MagicMock()
            mock_response_200 = MagicMock()
            mock_response_200.status_code = 200
            mock_response_200.raise_for_status = Mock()
            
            # First call raises RequestError, second succeeds
            mock_client.get.side_effect = [
                httpx.RequestError("Connection error", request=Mock()),
                mock_response_200
            ]
            mock_client_class.return_value = mock_client
            
            with patch('provchain.utils.network.time.sleep'):
                client = HTTPClient(base_url="https://api.example.com", max_retries=3)
                response = client.get("/test")
                
                assert response.status_code == 200

    def test_http_client_get_request_error_max_retries(self):
        """Test GET request raises RequestError after max retries"""
        with patch('provchain.utils.network.httpx.Client') as mock_client_class:
            mock_client = MagicMock()
            mock_client.get.side_effect = httpx.RequestError("Connection error", request=Mock())
            mock_client_class.return_value = mock_client
            
            with patch('provchain.utils.network.time.sleep'):
                client = HTTPClient(base_url="https://api.example.com", max_retries=2)
                
                with pytest.raises(httpx.RequestError):
                    client.get("/test")

    def test_http_client_get_http_status_error_max_retries(self):
        """Test GET request raises HTTPStatusError after max retries"""
        with patch('provchain.utils.network.httpx.Client') as mock_client_class:
            mock_client = MagicMock()
            mock_response_500 = MagicMock()
            mock_response_500.status_code = 500
            mock_response_500.raise_for_status.side_effect = httpx.HTTPStatusError(
                "Server Error", request=Mock(), response=mock_response_500
            )
            
            mock_client.get.return_value = mock_response_500
            mock_client_class.return_value = mock_client
            
            with patch('provchain.utils.network.time.sleep'):
                client = HTTPClient(base_url="https://api.example.com", max_retries=1)
                
                with pytest.raises(httpx.HTTPStatusError):
                    client.get("/test")

    def test_http_client_get_http_status_error_client_error_no_retry(self):
        """Test GET request raises HTTPStatusError immediately for client errors (4xx) - covers line 89"""
        with patch('provchain.utils.network.httpx.Client') as mock_client_class:
            mock_client = MagicMock()
            mock_response_404 = MagicMock()
            mock_response_404.status_code = 404
            mock_response_404.raise_for_status.side_effect = httpx.HTTPStatusError(
                "Not Found", request=Mock(), response=mock_response_404
            )
            
            mock_client.get.return_value = mock_response_404
            mock_client_class.return_value = mock_client
            
            client = HTTPClient(base_url="https://api.example.com", max_retries=3)
            
            with pytest.raises(httpx.HTTPStatusError):
                client.get("/test")

    def test_http_client_post_success(self):
        """Test successful POST request"""
        with patch('provchain.utils.network.httpx.Client') as mock_client_class:
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            mock_client.post.return_value = mock_response
            mock_client_class.return_value = mock_client
            
            client = HTTPClient(base_url="https://api.example.com")
            response = client.post("/test", json={"key": "value"})
            
            assert response.status_code == 200
            mock_response.raise_for_status.assert_called_once()

    def test_http_client_post_with_retry(self):
        """Test POST request with retry on server error"""
        with patch('provchain.utils.network.httpx.Client') as mock_client_class:
            mock_client = MagicMock()
            mock_response_500 = MagicMock()
            mock_response_500.status_code = 500
            mock_response_500.raise_for_status.side_effect = httpx.HTTPStatusError(
                "Server Error", request=Mock(), response=mock_response_500
            )
            
            mock_response_200 = MagicMock()
            mock_response_200.status_code = 200
            mock_response_200.raise_for_status = Mock()
            
            mock_client.post.side_effect = [mock_response_500, mock_response_200]
            mock_client_class.return_value = mock_client
            
            with patch('provchain.utils.network.time.sleep'):
                client = HTTPClient(base_url="https://api.example.com", max_retries=3)
                response = client.post("/test", json={"key": "value"})
                
                assert response.status_code == 200

    def test_http_client_post_request_error_retry(self):
        """Test POST request with retry on RequestError"""
        with patch('provchain.utils.network.httpx.Client') as mock_client_class:
            mock_client = MagicMock()
            mock_response_200 = MagicMock()
            mock_response_200.status_code = 200
            mock_response_200.raise_for_status = Mock()
            
            # First call raises RequestError, second succeeds
            mock_client.post.side_effect = [
                httpx.RequestError("Connection error", request=Mock()),
                mock_response_200
            ]
            mock_client_class.return_value = mock_client
            
            with patch('provchain.utils.network.time.sleep'):
                client = HTTPClient(base_url="https://api.example.com", max_retries=3)
                response = client.post("/test", json={"key": "value"})
                
                assert response.status_code == 200

    def test_http_client_post_request_error_max_retries(self):
        """Test POST request raises RequestError after max retries"""
        with patch('provchain.utils.network.httpx.Client') as mock_client_class:
            mock_client = MagicMock()
            mock_client.post.side_effect = httpx.RequestError("Connection error", request=Mock())
            mock_client_class.return_value = mock_client
            
            with patch('provchain.utils.network.time.sleep'):
                client = HTTPClient(base_url="https://api.example.com", max_retries=2)
                
                with pytest.raises(httpx.RequestError):
                    client.post("/test", json={"key": "value"})

    def test_http_client_post_http_status_error_client_error_no_retry(self):
        """Test POST request raises HTTPStatusError immediately for client errors (4xx) - covers line 89"""
        with patch('provchain.utils.network.httpx.Client') as mock_client_class:
            mock_client = MagicMock()
            mock_response_400 = MagicMock()
            mock_response_400.status_code = 400
            mock_response_400.raise_for_status.side_effect = httpx.HTTPStatusError(
                "Bad Request", request=Mock(), response=mock_response_400
            )
            
            mock_client.post.return_value = mock_response_400
            mock_client_class.return_value = mock_client
            
            client = HTTPClient(base_url="https://api.example.com", max_retries=3)
            
            with pytest.raises(httpx.HTTPStatusError):
                client.post("/test", json={"key": "value"})

    def test_http_client_close(self):
        """Test closing HTTP client"""
        with patch('provchain.utils.network.httpx.Client') as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            
            client = HTTPClient(base_url="https://api.example.com")
            client.close()
            mock_client.close.assert_called_once()

    def test_http_client_context_manager(self):
        """Test HTTP client as context manager"""
        with patch('provchain.utils.network.httpx.Client') as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            
            with HTTPClient() as client:
                assert client is not None
            
            mock_client.close.assert_called_once()


class TestAsyncHTTPClient:
    """Test cases for AsyncHTTPClient"""

    def test_async_http_client_init_default(self):
        """Test async HTTP client initialization with defaults"""
        with patch('provchain.utils.network.httpx.AsyncClient') as mock_client:
            client = AsyncHTTPClient()
            
            assert client.base_url is None
            assert client.timeout == 30.0
            assert client.max_retries == 3
            mock_client.assert_called_once()

    def test_async_http_client_init_custom(self):
        """Test async HTTP client initialization with custom parameters"""
        client = AsyncHTTPClient(
            base_url="https://api.example.com",
            rate_limit=50,
            time_window=30.0,
            timeout=60.0,
            max_retries=5
        )
        
        assert client.base_url == "https://api.example.com"
        assert client.timeout == 60.0
        assert client.max_retries == 5

    @pytest.mark.asyncio
    async def test_async_http_client_get_success(self):
        """Test successful async GET request"""
        with patch('provchain.utils.network.httpx.AsyncClient') as mock_client_class:
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.raise_for_status = Mock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client_class.return_value = mock_client
            
            client = AsyncHTTPClient(base_url="https://api.example.com")
            response = await client.get("/test")
            
            assert response.status_code == 200
            mock_response.raise_for_status.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_http_client_get_with_retry(self):
        """Test async GET request with retry on server error"""
        with patch('provchain.utils.network.httpx.AsyncClient') as mock_client_class:
            mock_client = MagicMock()
            mock_response_500 = MagicMock()
            mock_response_500.status_code = 500
            mock_response_500.raise_for_status.side_effect = httpx.HTTPStatusError(
                "Server Error", request=Mock(), response=mock_response_500
            )
            
            mock_response_200 = MagicMock()
            mock_response_200.status_code = 200
            mock_response_200.raise_for_status = Mock()
            
            mock_client.get = AsyncMock(side_effect=[mock_response_500, mock_response_200])
            mock_client_class.return_value = mock_client
            
            with patch('provchain.utils.network.asyncio.sleep') as mock_sleep:
                mock_sleep.return_value = AsyncMock()
                client = AsyncHTTPClient(base_url="https://api.example.com", max_retries=3)
                response = await client.get("/test")
                
                assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_async_http_client_get_request_error_retry(self):
        """Test async GET request with retry on RequestError"""
        with patch('provchain.utils.network.httpx.AsyncClient') as mock_client_class:
            mock_client = MagicMock()
            mock_response_200 = MagicMock()
            mock_response_200.status_code = 200
            mock_response_200.raise_for_status = Mock()
            
            # First call raises RequestError, second succeeds
            mock_client.get = AsyncMock(side_effect=[
                httpx.RequestError("Connection error", request=Mock()),
                mock_response_200
            ])
            mock_client_class.return_value = mock_client
            
            with patch('provchain.utils.network.asyncio.sleep') as mock_sleep:
                mock_sleep.return_value = AsyncMock()
                client = AsyncHTTPClient(base_url="https://api.example.com", max_retries=3)
                response = await client.get("/test")
                
                assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_async_http_client_get_request_error_max_retries(self):
        """Test async GET request raises RequestError after max retries"""
        with patch('provchain.utils.network.httpx.AsyncClient') as mock_client_class:
            mock_client = MagicMock()
            mock_client.get = AsyncMock(side_effect=httpx.RequestError("Connection error", request=Mock()))
            mock_client_class.return_value = mock_client
            
            with patch('provchain.utils.network.asyncio.sleep') as mock_sleep:
                mock_sleep.return_value = AsyncMock()
                client = AsyncHTTPClient(base_url="https://api.example.com", max_retries=2)
                
                with pytest.raises(httpx.RequestError):
                    await client.get("/test")

    @pytest.mark.asyncio
    async def test_async_http_client_get_http_status_error_max_retries(self):
        """Test async GET request raises HTTPStatusError after max retries"""
        with patch('provchain.utils.network.httpx.AsyncClient') as mock_client_class:
            mock_client = MagicMock()
            mock_response_500 = MagicMock()
            mock_response_500.status_code = 500
            mock_response_500.raise_for_status.side_effect = httpx.HTTPStatusError(
                "Server Error", request=Mock(), response=mock_response_500
            )
            
            mock_client.get = AsyncMock(return_value=mock_response_500)
            mock_client_class.return_value = mock_client
            
            with patch('provchain.utils.network.asyncio.sleep') as mock_sleep:
                mock_sleep.return_value = AsyncMock()
                client = AsyncHTTPClient(base_url="https://api.example.com", max_retries=1)
                
                with pytest.raises(httpx.HTTPStatusError):
                    await client.get("/test")

    @pytest.mark.asyncio
    async def test_async_http_client_close(self):
        """Test closing async HTTP client"""
        with patch('provchain.utils.network.httpx.AsyncClient') as mock_client_class:
            mock_client = MagicMock()
            mock_client.aclose = AsyncMock()
            mock_client_class.return_value = mock_client
            
            client = AsyncHTTPClient(base_url="https://api.example.com")
            await client.close()
            mock_client.aclose.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_http_client_context_manager(self):
        """Test async HTTP client as context manager"""
        with patch('provchain.utils.network.httpx.AsyncClient') as mock_client_class:
            mock_client = MagicMock()
            mock_client.aclose = AsyncMock()
            mock_client_class.return_value = mock_client
            
            async with AsyncHTTPClient(base_url="https://api.example.com") as client:
                assert client is not None
            
            mock_client.aclose.assert_called_once()

