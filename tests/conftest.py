"""Pytest configuration and fixtures"""

import os
import shutil
import tempfile
import uuid
from pathlib import Path

import pytest

from provchain.data.cache import Cache
from provchain.data.db import Database

TEST_TEMP_ROOT = Path(__file__).resolve().parent / "_sandbox_tmp"
TEST_TEMP_ROOT.mkdir(parents=True, exist_ok=True)

# Keep Python tempfile usage inside the repo so tests remain sandbox-friendly.
os.environ["TMP"] = str(TEST_TEMP_ROOT)
os.environ["TEMP"] = str(TEST_TEMP_ROOT)
os.environ.setdefault("TMPDIR", str(TEST_TEMP_ROOT))
tempfile.tempdir = str(TEST_TEMP_ROOT)


@pytest.fixture
def tmp_path():
    """Provide a writable per-test temp directory inside the repo."""
    path = TEST_TEMP_ROOT / f"case-{uuid.uuid4().hex}"
    path.mkdir(parents=True, exist_ok=False)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def temp_db():
    """Create temporary database for testing"""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = Path(f.name)
    db = Database(db_path=db_path)
    yield db
    # Close all connections before deleting on Windows
    db.engine.dispose()
    try:
        db_path.unlink(missing_ok=True)
    except PermissionError:
        # On Windows, sometimes the file is still locked
        # Try again after a brief delay
        import time
        time.sleep(0.1)
        try:
            db_path.unlink(missing_ok=True)
        except PermissionError:
            # If still locked, just skip deletion (temp file will be cleaned up later)
            pass


@pytest.fixture
def cache(temp_db):
    """Create cache for testing"""
    return Cache(temp_db)


@pytest.fixture
def sample_package_metadata():
    """Sample package metadata for testing"""
    from datetime import datetime, timezone

    from provchain.data.models import MaintainerInfo, PackageIdentifier, PackageMetadata

    return PackageMetadata(
        identifier=PackageIdentifier(ecosystem="pypi", name="test-package", version="1.0.0"),
        description="A test package",
        homepage="https://example.com",
        repository="https://github.com/example/test-package",
        license="MIT",
        maintainers=[
            MaintainerInfo(
                username="testuser",
                email="test@example.com",
                account_created=datetime(2020, 1, 1, tzinfo=timezone.utc),
            )
        ],
        dependencies=[],
        first_release=datetime(2020, 1, 1, tzinfo=timezone.utc),
        latest_release=datetime(2024, 1, 1, tzinfo=timezone.utc),
        download_count=1000,
    )

