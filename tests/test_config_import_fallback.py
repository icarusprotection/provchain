"""Test config import fallback (lines 8-13)"""

import importlib
import sys
from unittest.mock import MagicMock, patch


def test_config_tomllib_fallback_to_tomli():
    """Test that config falls back to tomli when tomllib is not available (Python < 3.11)"""
    # Save original modules
    original_tomli = sys.modules.get("tomli")
    original_tomllib = sys.modules.get("tomllib")
    original_config = sys.modules.get("provchain.config")

    # Create a mock tomli module
    mock_tomli = MagicMock()
    mock_tomli.load = MagicMock()

    # Remove from sys.modules to force re-import
    if "provchain.config" in sys.modules:
        del sys.modules["provchain.config"]
    if "tomli" in sys.modules:
        del sys.modules["tomli"]
    if "tomllib" in sys.modules:
        del sys.modules["tomllib"]

    # Mock __import__ to raise ImportError for tomllib, but succeed for tomli
    original_import = __import__

    def mock_import(name, *args, **kwargs):
        if name == "tomllib":
            raise ImportError("No module named 'tomllib'")
        if name == "tomli":
            sys.modules["tomli"] = mock_tomli
            return mock_tomli
        return original_import(name, *args, **kwargs)

    try:
        with patch("builtins.__import__", side_effect=mock_import):
            import provchain.config

            importlib.reload(provchain.config)

            # After fallback, tomli should be the mock (via tomli backport)
            assert provchain.config.tomli is not None
            assert provchain.config.tomli is mock_tomli
            assert hasattr(provchain.config.tomli, "load")
    finally:
        if "provchain.config" in sys.modules:
            del sys.modules["provchain.config"]
        if original_tomli is not None:
            sys.modules["tomli"] = original_tomli
        elif "tomli" in sys.modules:
            del sys.modules["tomli"]
        if original_tomllib is not None:
            sys.modules["tomllib"] = original_tomllib
        elif "tomllib" in sys.modules:
            del sys.modules["tomllib"]
        if original_config is not None:
            import provchain.config

            importlib.reload(provchain.config)


def test_config_tomli_import_fallback_both_fail():
    """Test that config sets tomli to None when both imports fail - covers line 13"""
    # Save original modules
    original_tomli = sys.modules.get("tomli")
    original_tomllib = sys.modules.get("tomllib")
    original_config = sys.modules.get("provchain.config")

    # Remove from sys.modules to force re-import
    if "provchain.config" in sys.modules:
        del sys.modules["provchain.config"]
    if "tomli" in sys.modules:
        del sys.modules["tomli"]
    if "tomllib" in sys.modules:
        del sys.modules["tomllib"]

    # Mock __import__ to raise ImportError for both
    original_import = __import__

    def mock_import(name, *args, **kwargs):
        if name in ("tomli", "tomllib"):
            raise ImportError(f"No module named '{name}'")
        return original_import(name, *args, **kwargs)

    try:
        with patch("builtins.__import__", side_effect=mock_import):
            import provchain.config

            importlib.reload(provchain.config)

            # After both imports fail, tomli should be None (line 13)
            assert provchain.config.tomli is None
    finally:
        if "provchain.config" in sys.modules:
            del sys.modules["provchain.config"]
        if original_tomli is not None:
            sys.modules["tomli"] = original_tomli
        elif "tomli" in sys.modules:
            del sys.modules["tomli"]
        if original_tomllib is not None:
            sys.modules["tomllib"] = original_tomllib
        elif "tomllib" in sys.modules:
            del sys.modules["tomllib"]
        if original_config is not None:
            import provchain.config

            importlib.reload(provchain.config)
