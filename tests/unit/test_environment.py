"""
Unit tests for the signing service environment utility functions.
"""

import os
import pytest
import tempfile
from unittest.mock import patch

from app.utils.environment import loadConfigValueFromFileOrEnvironment, loadBoolConfigValue


class TestLoadConfigValueFromFileOrEnvironment:
    """Tests for loadConfigValueFromFileOrEnvironment."""

    def test_returns_default_when_no_env_or_file(self):
        """Returns default value when neither env var nor file is set."""
        with patch.dict(os.environ, {}, clear=True):
            result = loadConfigValueFromFileOrEnvironment('NONEXISTENT_KEY', 'default_val')
        assert result == 'default_val'

    def test_returns_env_var_value(self):
        """Returns the environment variable value when set."""
        with patch.dict(os.environ, {'MY_KEY': 'env_value'}, clear=True):
            result = loadConfigValueFromFileOrEnvironment('MY_KEY', 'default')
        assert result == 'env_value'

    def test_returns_file_content_over_env_var(self):
        """File content takes precedence over environment variable."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('file_value')
            f.flush()
            try:
                with patch.dict(os.environ, {
                    'MY_KEY': 'env_value',
                    'MY_KEY_FILE': f.name
                }, clear=True):
                    result = loadConfigValueFromFileOrEnvironment('MY_KEY', 'default')
                assert result == 'file_value'
            finally:
                os.unlink(f.name)

    def test_strips_whitespace_from_file(self):
        """File content is stripped of leading/trailing whitespace."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('  trimmed_value  \n')
            f.flush()
            try:
                with patch.dict(os.environ, {'MY_KEY_FILE': f.name}, clear=True):
                    result = loadConfigValueFromFileOrEnvironment('MY_KEY', 'default')
                assert result == 'trimmed_value'
            finally:
                os.unlink(f.name)

    def test_raises_on_nonexistent_file(self):
        """Raises FileNotFoundError when file path doesn't exist."""
        with patch.dict(os.environ, {'MY_KEY_FILE': '/nonexistent/path.txt'}, clear=True):
            with pytest.raises(FileNotFoundError):
                loadConfigValueFromFileOrEnvironment('MY_KEY', 'default')

    def test_returns_env_when_file_is_empty(self):
        """Falls back to env var when file exists but is empty."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('')
            f.flush()
            try:
                with patch.dict(os.environ, {
                    'MY_KEY': 'env_value',
                    'MY_KEY_FILE': f.name
                }, clear=True):
                    result = loadConfigValueFromFileOrEnvironment('MY_KEY', 'default')
                assert result == 'env_value'
            finally:
                os.unlink(f.name)

    def test_returns_default_when_file_empty_and_no_env(self):
        """Returns default when file is empty and no env var set."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('   ')
            f.flush()
            try:
                with patch.dict(os.environ, {'MY_KEY_FILE': f.name}, clear=True):
                    result = loadConfigValueFromFileOrEnvironment('MY_KEY', 'fallback')
                assert result == 'fallback'
            finally:
                os.unlink(f.name)

    def test_raises_on_directory_path(self):
        """Raises FileNotFoundError when path is a directory, not a file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {'MY_KEY_FILE': tmpdir}, clear=True):
                with pytest.raises(FileNotFoundError):
                    loadConfigValueFromFileOrEnvironment('MY_KEY', 'default')


class TestLoadBoolConfigValue:
    """Tests for loadBoolConfigValue."""

    @pytest.mark.parametrize("value,expected", [
        ('true', True),
        ('True', True),
        ('TRUE', True),
        ('yes', True),
        ('Yes', True),
        ('on', True),
        ('ON', True),
        ('1', True),
    ])
    def test_true_values(self, value, expected):
        """Recognises various true string representations."""
        with patch.dict(os.environ, {'TEST_BOOL': value}):
            assert loadBoolConfigValue('TEST_BOOL', 'false') is expected

    @pytest.mark.parametrize("value,expected", [
        ('false', False),
        ('False', False),
        ('FALSE', False),
        ('no', False),
        ('No', False),
        ('off', False),
        ('OFF', False),
        ('0', False),
    ])
    def test_false_values(self, value, expected):
        """Recognises various false string representations."""
        with patch.dict(os.environ, {'TEST_BOOL': value}):
            assert loadBoolConfigValue('TEST_BOOL', 'true') is expected

    def test_default_value_used_when_not_set(self):
        """Uses default when environment variable is not set."""
        with patch.dict(os.environ, {}, clear=True):
            assert loadBoolConfigValue('UNSET_BOOL', 'true') is True
            assert loadBoolConfigValue('UNSET_BOOL', 'false') is False

    def test_unknown_string_treated_as_true_with_default_prefer(self):
        """Unknown strings are treated as True when prefer=False (default)."""
        with patch.dict(os.environ, {'TEST_BOOL': 'maybe'}):
            assert loadBoolConfigValue('TEST_BOOL', 'false') is True

    def test_unknown_string_treated_as_false_with_prefer_true(self):
        """Unknown strings are treated as False when prefer=True."""
        with patch.dict(os.environ, {'TEST_BOOL': 'maybe'}):
            assert loadBoolConfigValue('TEST_BOOL', 'false', prefer=True) is False

    def test_prefer_true_returns_true_only_for_explicit_true(self):
        """With prefer=True, only explicit true values return True."""
        with patch.dict(os.environ, {'TEST_BOOL': 'true'}):
            assert loadBoolConfigValue('TEST_BOOL', 'false', prefer=True) is True
        with patch.dict(os.environ, {'TEST_BOOL': '1'}):
            assert loadBoolConfigValue('TEST_BOOL', 'false', prefer=True) is True

    def test_prefer_false_returns_false_only_for_explicit_false(self):
        """With prefer=False (default), only explicit false values return False."""
        with patch.dict(os.environ, {'TEST_BOOL': 'false'}):
            assert loadBoolConfigValue('TEST_BOOL', 'true', prefer=False) is False
        with patch.dict(os.environ, {'TEST_BOOL': '0'}):
            assert loadBoolConfigValue('TEST_BOOL', 'true', prefer=False) is False

    def test_case_insensitivity(self):
        """Boolean parsing is case-insensitive."""
        with patch.dict(os.environ, {'TEST_BOOL': 'tRuE'}):
            assert loadBoolConfigValue('TEST_BOOL', 'false') is True
        with patch.dict(os.environ, {'TEST_BOOL': 'fAlSe'}):
            assert loadBoolConfigValue('TEST_BOOL', 'true') is False
