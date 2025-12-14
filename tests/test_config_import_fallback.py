"""Test config import fallback (lines 8-13)"""

import sys
import importlib
import pytest
from unittest.mock import patch, MagicMock


def test_config_tomli_import_fallback_to_tomllib():
    """Test that config falls back to tomllib when tomli is not available - covers lines 8-13, specifically line 11"""
    # Save original modules
    original_tomli = sys.modules.get('tomli')
    original_tomllib = sys.modules.get('tomllib')
    original_config = sys.modules.get('provchain.config')
    
    # Create a mock tomllib module
    mock_tomllib = MagicMock()
    mock_tomllib.load = MagicMock()
    
    # Remove from sys.modules to force re-import
    if 'provchain.config' in sys.modules:
        del sys.modules['provchain.config']
    # Remove tomli and tomllib to force re-import through our mock
    if 'tomli' in sys.modules:
        del sys.modules['tomli']
    if 'tomllib' in sys.modules:
        del sys.modules['tomllib']
    
    # Mock __import__ to raise ImportError for tomli, but succeed for tomllib
    original_import = __import__
    import_calls = []
    
    def mock_import(name, globals=None, locals=None, fromlist=(), level=0):
        import_calls.append(name)
        # Check if this is the first attempt to import tomli (line 7)
        # The second attempt (line 10) is "import tomli as tomllib", which still calls __import__('tomli', ...)
        # We need to track whether this is the first or second attempt
        if name == 'tomli':
            # Check if tomli has been attempted before by checking import_calls
            tomli_count = import_calls.count('tomli')
            if tomli_count == 1:
                # First call (try tomli) - raise ImportError (line 8)
                raise ImportError("No module named 'tomli'")
            else:
                # Second call (try tomli as tomllib on line 10) - succeed
                # Inject mock into sys.modules as both tomli and tomllib
                sys.modules['tomli'] = mock_tomllib
                sys.modules['tomllib'] = mock_tomllib
                return mock_tomllib
        else:
            return original_import(name, globals, locals, fromlist, level)
    
    try:
        # Patch __import__ before importing config
        with patch('builtins.__import__', side_effect=mock_import):
            # Import the config module - this will execute the import statements
            # Since tomli is not in sys.modules and our mock raises ImportError,
            # it should fall back to tomllib
            import provchain.config
            # Reload to ensure the import statements are re-executed
            importlib.reload(provchain.config)
            
            # After fallback, tomli should be set to tomllib (line 11)
            assert provchain.config.tomli is not None, f"tomli is None, import_calls: {import_calls}"
            # Check that tomli is the mock_tomllib (line 11: tomli = tomllib)
            assert provchain.config.tomli is mock_tomllib or provchain.config.tomli is sys.modules.get('tomllib')
            assert hasattr(provchain.config.tomli, 'load')
            # Verify both imports were attempted
            assert 'tomli' in import_calls or 'tomli' in [c for c in import_calls if 'tomli' in str(c)]
    finally:
        # Clean up
        if 'provchain.config' in sys.modules:
            del sys.modules['provchain.config']
        # Restore tomli
        if original_tomli is not None:
            sys.modules['tomli'] = original_tomli
        elif 'tomli' in sys.modules:
            del sys.modules['tomli']
        # Restore tomllib
        if original_tomllib is not None:
            sys.modules['tomllib'] = original_tomllib
        elif 'tomllib' in sys.modules and 'tomli' not in str(sys.modules.get('tomllib', '')):
            # Only delete if it's not the real tomllib
            del sys.modules['tomllib']
        # Reload config module to restore original state
        if original_config is not None:
            import provchain.config
            importlib.reload(provchain.config)


def test_config_tomli_import_fallback_both_fail():
    """Test that config sets tomli to None when both imports fail - covers line 13"""
    # Save original modules
    original_tomli = sys.modules.get('tomli')
    original_tomllib = sys.modules.get('tomllib')
    original_config = sys.modules.get('provchain.config')
    
    # Remove from sys.modules to force re-import
    if 'provchain.config' in sys.modules:
        del sys.modules['provchain.config']
    if 'tomli' in sys.modules:
        del sys.modules['tomli']
    if 'tomllib' in sys.modules:
        del sys.modules['tomllib']
    
    # Mock __import__ to raise ImportError for both
    original_import = __import__
    
    def mock_import(name, *args, **kwargs):
        if name == 'tomli':
            # First call (try tomli) - raise ImportError (line 8)
            raise ImportError("No module named 'tomli'")
        elif name == 'tomllib':
            # Second call (try tomli as tomllib) - also raise ImportError (line 10)
            raise ImportError("No module named 'tomllib'")
        else:
            return original_import(name, *args, **kwargs)
    
    try:
        with patch('builtins.__import__', side_effect=mock_import):
            # Import the config module to trigger the import fallback (lines 8-13)
            import provchain.config
            importlib.reload(provchain.config)
            
            # After both imports fail, tomli should be None (line 13)
            assert provchain.config.tomli is None
    finally:
        # Restore original modules
        if 'provchain.config' in sys.modules:
            del sys.modules['provchain.config']
        if 'tomli' in sys.modules and original_tomli is None:
            del sys.modules['tomli']
        elif original_tomli is not None:
            sys.modules['tomli'] = original_tomli
        if 'tomllib' in sys.modules and original_tomllib is None:
            del sys.modules['tomllib']
        elif original_tomllib is not None:
            sys.modules['tomllib'] = original_tomllib
        # Reload config module to restore original state
        if original_config is not None:
            import provchain.config
            importlib.reload(provchain.config)

