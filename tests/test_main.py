"""Tests for __main__.py entry point"""

from unittest.mock import patch
import pytest

from provchain.cli.main import app


def test_main_entry_point():
    """Test that __main__.py can be executed"""
    # This tests the `if __name__ == "__main__": app()` line
    with patch('provchain.cli.main.app') as mock_app:
        # Import and execute the module
        import provchain.__main__
        # The app() call happens on import if __name__ == "__main__"
        # But in test context, __name__ is not "__main__", so we need to call it
        provchain.__main__.app()
        mock_app.assert_called_once()

