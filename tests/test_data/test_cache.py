"""Tests for caching layer"""

import pytest
from datetime import timedelta
from unittest.mock import patch

from provchain.data.cache import Cache


def test_cache_set_and_get(cache):
    """Test setting and getting cached values"""
    cache.set("test", {"key": "value"}, timedelta(hours=1), "namespace", "key")
    
    result = cache.get("test", "namespace", "key")
    assert result is not None
    assert result["key"] == "value"


def test_cache_miss(cache):
    """Test cache miss returns None"""
    result = cache.get("test", "namespace", "nonexistent")
    assert result is None


def test_cache_expiration(cache):
    """Test cache expiration"""
    # Set with very short TTL
    cache.set("test", {"key": "value"}, timedelta(seconds=0.1), "namespace", "key")
    
    # Should still be available immediately
    result = cache.get("test", "namespace", "key")
    assert result is not None
    
    # Wait for expiration
    import time
    time.sleep(0.2)
    
    # Should be expired
    result = cache.get("test", "namespace", "key")
    assert result is None


def test_cache_invalidate(cache):
    """Test invalidating cached value"""
    cache.set("test", {"key": "value"}, timedelta(hours=1), "namespace", "key")
    
    # Should be available
    result = cache.get("test", "namespace", "key")
    assert result is not None
    
    # Invalidate
    cache.invalidate("test", "namespace", "key")
    
    # Should be gone
    result = cache.get("test", "namespace", "key")
    assert result is None


def test_cache_clear(cache):
    """Test clearing all cache entries"""
    cache.set("test", {"key1": "value1"}, timedelta(hours=1), "namespace1", "key1")
    cache.set("test", {"key2": "value2"}, timedelta(hours=1), "namespace2", "key2")
    
    # Both should be available
    assert cache.get("test", "namespace1", "key1") is not None
    assert cache.get("test", "namespace2", "key2") is not None
    
    # Clear all
    cache.clear()
    
    # Both should be gone
    assert cache.get("test", "namespace1", "key1") is None
    assert cache.get("test", "namespace2", "key2") is None


def test_cache_default_ttl(cache):
    """Test cache uses default TTL when not specified"""
    cache.set("test", {"key": "value"}, None, "namespace", "key")
    
    # Should be available
    result = cache.get("test", "namespace", "key")
    assert result is not None


def test_cache_key_generation(cache):
    """Test cache key generation is consistent"""
    # Same arguments should generate same key
    cache.set("test", {"key": "value1"}, timedelta(hours=1), "namespace", "key")
    cache.set("test", {"key": "value2"}, timedelta(hours=1), "namespace", "key")
    
    # Second set should overwrite first
    result = cache.get("test", "namespace", "key")
    assert result["key"] == "value2"


def test_cache_get_from_database_not_expired(cache):
    """Test getting cache from database when not expired - covers lines 56-62"""
    # Set a value in the database cache
    cache.set("test", {"key": "db_value"}, timedelta(hours=1), "namespace", "key")
    
    # Get the key that was generated
    key = cache._make_key("test", "namespace", "key")
    
    # Clear memory cache to force database lookup
    cache._cache_table.clear()
    
    # Verify it's not in memory
    assert key not in cache._cache_table
    
    # Get should retrieve from database and store in memory (lines 56-62)
    result = cache.get("test", "namespace", "key")
    
    assert result is not None
    assert result["key"] == "db_value"
    # Should be stored in memory cache now (lines 58-61)
    assert key in cache._cache_table
    assert cache._cache_table[key]["value"]["key"] == "db_value"


def test_cache_set_exception_handling(cache):
    """Test exception handling in set() method - covers lines 116-118"""
    from unittest.mock import patch, MagicMock
    
    # Create a mock session
    mock_session = MagicMock()
    mock_session.query.return_value.filter_by.return_value.first.return_value = None
    # Make commit raise an exception
    mock_session.commit.side_effect = Exception("Database error")
    
    # Patch Session() to return our mocked session
    with patch.object(cache.db, 'Session', return_value=mock_session):
        # set() should rollback and re-raise (lines 116-118)
        with pytest.raises(Exception, match="Database error"):
            cache.set("test", {"key": "value"}, timedelta(hours=1), "namespace", "key")
        
        # Verify rollback was called (line 117)
        mock_session.rollback.assert_called_once()

