"""Caching layer for API responses"""

import hashlib
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from provchain.data.db import Database


class Cache:
    """TTL-based cache for API responses"""

    def __init__(self, db: Database, default_ttl_hours: int = 24):
        self.db = db
        self.default_ttl = timedelta(hours=default_ttl_hours)
        self._cache_table = {}  # In-memory cache for quick access

    def _make_key(self, service: str, *args: Any, **kwargs: Any) -> str:
        """Generate cache key from service and arguments"""
        key_data = {
            "service": service,
            "args": args,
            "kwargs": sorted(kwargs.items()),
        }
        key_str = json.dumps(key_data, sort_keys=True)
        return hashlib.sha256(key_str.encode()).hexdigest()

    def get(self, service: str, *args: Any, **kwargs: Any) -> Any | None:
        """Get cached value if not expired"""
        key = self._make_key(service, *args, **kwargs)

        # Check in-memory cache first
        if key in self._cache_table:
            entry = self._cache_table[key]
            if entry["expires_at"] > datetime.now(timezone.utc):
                return entry["value"]
            else:
                del self._cache_table[key]

        # Check database cache
        session = self.db.Session()
        try:
            from provchain.data.db import ConfigRecord

            cache_key = f"cache:{key}"
            config = session.query(ConfigRecord).filter_by(key=cache_key).first()

            if config:
                cache_data = json.loads(config.value_json)
                expires_at = datetime.fromisoformat(cache_data["expires_at"])

                if expires_at > datetime.now(timezone.utc):
                    value = cache_data["value"]
                    # Store in memory cache
                    self._cache_table[key] = {
                        "value": value,
                        "expires_at": expires_at,
                    }
                    return value
                else:
                    # Expired, remove it
                    session.delete(config)
                    session.commit()
        finally:
            session.close()

        return None

    def set(
        self,
        service: str,
        value: Any,
        ttl: timedelta | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """Set cached value with TTL"""
        key = self._make_key(service, *args, **kwargs)
        ttl = ttl or self.default_ttl
        expires_at = datetime.now(timezone.utc) + ttl

        # Store in memory cache
        self._cache_table[key] = {
            "value": value,
            "expires_at": expires_at,
        }

        # Store in database cache
        session = self.db.Session()
        try:
            from provchain.data.db import ConfigRecord

            cache_key = f"cache:{key}"
            cache_data = {
                "value": value,
                "expires_at": expires_at.isoformat(),
            }

            existing = session.query(ConfigRecord).filter_by(key=cache_key).first()
            if existing:
                existing.value_json = json.dumps(cache_data)
                existing.updated_at = datetime.now(timezone.utc)
            else:
                session.add(
                    ConfigRecord(
                        key=cache_key,
                        value_json=json.dumps(cache_data),
                        updated_at=datetime.now(timezone.utc),
                    )
                )

            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def invalidate(self, service: str, *args: Any, **kwargs: Any) -> None:
        """Invalidate cached value"""
        key = self._make_key(service, *args, **kwargs)

        # Remove from memory cache
        if key in self._cache_table:
            del self._cache_table[key]

        # Remove from database cache
        session = self.db.Session()
        try:
            from provchain.data.db import ConfigRecord

            cache_key = f"cache:{key}"
            config = session.query(ConfigRecord).filter_by(key=cache_key).first()
            if config:
                session.delete(config)
                session.commit()
        finally:
            session.close()

    def clear(self) -> None:
        """Clear all cache entries"""
        self._cache_table.clear()

        session = self.db.Session()
        try:
            from provchain.data.db import ConfigRecord

            session.query(ConfigRecord).filter(ConfigRecord.key.like("cache:%")).delete()
            session.commit()
        finally:
            session.close()

