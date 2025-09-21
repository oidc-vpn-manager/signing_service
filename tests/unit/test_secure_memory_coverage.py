"""
Comprehensive tests for secure memory utility to achieve 100% coverage.
Tests edge cases, error conditions, and defensive coding patterns.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import os
import gc
import threading
import time
from flask import Flask

from app.utils.secure_memory import (
    secure_clear_variable,
    secure_key_context,
    SecureKeyManager,
    secure_zero_memory,
    create_secure_key_manager
)
from cryptography.hazmat.primitives.asymmetric import ed25519


@pytest.fixture
def app_context():
    """Create Flask app context for testing."""
    app = Flask(__name__)
    with app.app_context():
        yield app


class TestSecureClearVariable:
    """Test the secure_clear_variable function coverage."""

    def test_secure_clear_none_variable(self):
        """Test clearing None variable - covers line 29."""
        # This should return early without error
        secure_clear_variable(None)
        # No assertion needed - function should complete without error

    def test_secure_clear_variable_with_current_app_logging(self, app_context):
        """Test clearing variable with Flask current_app logging - covers lines 35-36."""
        # Create a mock object with private key attributes
        mock_var = Mock()
        mock_var._private_key = "secret"

        secure_clear_variable(mock_var)

        # Test completes successfully with Flask context available

    def test_secure_clear_variable_with_bytearray_attributes(self, app_context):
        """Test clearing variable with bytearray attributes - covers lines 44-47."""
        class MockKeyWithBytearray:
            def __init__(self):
                self.key_data = bytearray(b"secret_key_data")
                self._private_bytes = bytearray(b"private_data")

        mock_key = MockKeyWithBytearray()
        original_length = len(mock_key.key_data)

        secure_clear_variable(mock_key)

        # Verify bytearray attribute was cleared (set to None)
        assert mock_key.key_data is None
        assert mock_key._private_bytes is None

    def test_secure_clear_variable_with_long_string_attributes(self):
        """Test clearing variable with long string attributes - covers lines 48-50."""
        class MockKeyWithStrings:
            def __init__(self):
                self.long_string = "this_is_a_very_long_sensitive_string_data"
                self.short_string = "short"
                self.normal_attr = 123

        mock_key = MockKeyWithStrings()

        secure_clear_variable(mock_key)

        # Long string should be cleared (None), short string should remain
        assert mock_key.long_string is None
        assert mock_key.short_string == "short"  # Should not be cleared
        assert mock_key.normal_attr == 123  # Should not be cleared

    def test_secure_clear_variable_without_dict_attribute(self):
        """Test clearing variable without __dict__ attribute."""
        # Test with a simple immutable object
        secure_clear_variable(42)  # Integer has no __dict__
        secure_clear_variable("string")  # String has no __dict__
        secure_clear_variable([1, 2, 3])  # List has no __dict__

        # Should complete without error

    def test_secure_clear_variable_exception_handling(self, app_context):
        """Test exception handling during attribute clearing - covers lines 55-58."""
        class ProblematicKey:
            def __init__(self):
                self.good_attr = "normal"
                self.bad_attr = bytearray(b"sensitive")

        mock_key = ProblematicKey()

        # Mock setattr to raise exception
        original_setattr = setattr
        def failing_setattr(obj, name, value):
            if name == "bad_attr":
                raise RuntimeError("Cannot set this attribute")
            return original_setattr(obj, name, value)

        with patch('builtins.setattr', side_effect=failing_setattr):
            # Should not raise exception - should handle gracefully
            secure_clear_variable(mock_key)
            # Test completes successfully


class TestSecureKeyContext:
    """Test the secure_key_context context manager coverage."""

    def test_secure_key_context_with_loader_function(self, app_context):
        """Test secure key context with loader function - covers lines 114-123."""
        mock_key = Mock()
        mock_cert = Mock()

        def mock_loader():
            return (mock_key, mock_cert)

        with secure_key_context(mock_loader) as result:
            key, cert = result
            assert key is mock_key
            assert cert is mock_cert

    def test_secure_key_context_with_loader_single_return(self):
        """Test secure key context with loader function returning single key - covers line 118."""
        mock_key = Mock()

        def mock_loader():
            return mock_key

        with secure_key_context(mock_loader) as key:
            assert key is mock_key

    def test_secure_key_context_with_exception(self):
        """Test secure key context when exception occurs - covers exception path."""
        mock_key = Mock()
        mock_cert = Mock()

        def mock_loader():
            return (mock_key, mock_cert)

        with pytest.raises(ValueError):
            with secure_key_context(mock_loader) as result:
                key, cert = result
                assert key is mock_key
                # Simulate an exception during key usage
                raise ValueError("Something went wrong during key usage")

        # Should still attempt to clear even after exception

    def test_secure_key_context_with_none_key(self):
        """Test secure key context with None loader."""
        def none_loader():
            return None

        with secure_key_context(none_loader) as key:
            assert key is None

        # Should complete without error

    def test_secure_key_context_multiple_nested(self):
        """Test nested secure key contexts."""
        key1 = Mock()
        key1.data1 = bytearray(b"secret1")
        key2 = Mock()
        key2.data2 = bytearray(b"secret2")

        def loader1():
            return key1

        def loader2():
            return key2

        with secure_key_context(loader1) as k1:
            assert k1 is key1
            with secure_key_context(loader2) as k2:
                assert k2 is key2
                # Both keys should be accessible
                assert hasattr(k1, 'data1')
                assert hasattr(k2, 'data2')

        # Both should be cleared after contexts


class TestSecureKeyManager:
    """Test the SecureKeyManager class coverage."""

    def test_secure_key_manager_initialization(self):
        """Test SecureKeyManager initialization."""
        key = ed25519.Ed25519PrivateKey.generate()
        manager = SecureKeyManager(key)

        assert hasattr(manager, '_key')
        assert hasattr(manager, '_cert')
        assert hasattr(manager, '_cleared')
        assert manager._key is key
        assert manager._cert is None
        assert manager._cleared is False

    def test_secure_key_manager_initialization_with_cert(self):
        """Test SecureKeyManager initialization with certificate."""
        key = ed25519.Ed25519PrivateKey.generate()
        cert = Mock()  # Mock certificate

        manager = SecureKeyManager(key, cert)

        assert manager._key is key
        assert manager._cert is cert
        assert manager._cleared is False

    def test_secure_key_manager_key_property(self):
        """Test SecureKeyManager key property."""
        key = ed25519.Ed25519PrivateKey.generate()
        manager = SecureKeyManager(key)

        # Should return the key
        assert manager.key is key

        # Clear the manager
        manager.clear()

        # Should raise RuntimeError after clearing - covers lines 166-167
        with pytest.raises(RuntimeError, match="Key has been cleared"):
            _ = manager.key

    def test_secure_key_manager_cert_property(self):
        """Test SecureKeyManager cert property."""
        key = ed25519.Ed25519PrivateKey.generate()
        cert = Mock()
        manager = SecureKeyManager(key, cert)

        assert manager.cert is cert

    def test_secure_key_manager_manual_clear(self):
        """Test manual clearing of SecureKeyManager."""
        key = ed25519.Ed25519PrivateKey.generate()
        cert = Mock()
        manager = SecureKeyManager(key, cert)

        assert not manager._cleared

        # Clear manually
        manager.clear()

        assert manager._cleared
        assert manager._key is None
        assert manager._cert is None

    def test_secure_key_manager_manual_clear_without_flask_app(self):
        """Test manual clearing without Flask app context."""
        key = ed25519.Ed25519PrivateKey.generate()
        manager = SecureKeyManager(key)

        # Ensure no Flask app context
        with patch('app.utils.secure_memory.current_app', None):
            manager.clear()

        assert manager._cleared

    def test_secure_key_manager_double_clear(self):
        """Test clearing SecureKeyManager twice."""
        key = ed25519.Ed25519PrivateKey.generate()
        manager = SecureKeyManager(key)

        # Clear once
        manager.clear()
        assert manager._cleared

        # Clear again - should be safe
        manager.clear()
        assert manager._cleared

    def test_secure_key_manager_destructor(self):
        """Test SecureKeyManager destructor - covers lines 186-190."""
        key = ed25519.Ed25519PrivateKey.generate()

        # Create manager and let it go out of scope
        manager = SecureKeyManager(key)

        # Force destructor call
        del manager

        # Should complete without error

    def test_secure_key_manager_destructor_already_cleared(self):
        """Test SecureKeyManager destructor when already cleared."""
        key = ed25519.Ed25519PrivateKey.generate()
        manager = SecureKeyManager(key)

        # Clear manually first
        manager.clear()

        # Now destructor should not clear again
        del manager

        # Should complete without error

    def test_secure_key_manager_with_flask_logging(self, app_context):
        """Test SecureKeyManager with Flask logging - covers lines 160-161, 178-179."""
        key = ed25519.Ed25519PrivateKey.generate()

        # Create manager - should log initialization
        manager = SecureKeyManager(key)

        # Clear manually - should log clearing
        manager.clear()

        # Test completes successfully with Flask context available


class TestSecureMemoryEdgeCases:
    """Test edge cases and error conditions."""

    def test_secure_clear_variable_with_nested_objects(self, app_context):
        """Test clearing variables with nested object structures."""
        class NestedKey:
            def __init__(self):
                self.nested_obj = Mock()
                self.nested_obj.secret_data = bytearray(b"nested_secret")
                self.direct_secret = bytearray(b"direct_secret")

        nested_key = NestedKey()

        secure_clear_variable(nested_key)

        # Direct bytearray should be cleared (set to None)
        assert nested_key.direct_secret is None

    def test_secure_key_context_garbage_collection(self):
        """Test that secure key context works with garbage collection."""
        import gc

        key = Mock()
        key.data = bytearray(b"secret_to_be_collected")

        def key_loader():
            return key

        with secure_key_context(key_loader) as ctx_key:
            # Force garbage collection during context
            gc.collect()
            assert ctx_key is key

        # After context, attempt garbage collection
        gc.collect()

    def test_secure_memory_with_real_cryptography_key(self):
        """Test secure memory functions with actual cryptography objects."""
        from cryptography.hazmat.primitives.asymmetric import ed25519

        # Generate a real key
        private_key = ed25519.Ed25519PrivateKey.generate()

        def key_loader():
            return private_key

        # Test with real cryptography object
        with secure_key_context(key_loader) as key:
            assert key is private_key
            # Verify key is still functional
            assert hasattr(key, 'private_bytes')

        # Should complete without error

    def test_secure_clear_variable_immutable_types(self):
        """Test secure clearing with various immutable types."""
        # Test with various types that don't have __dict__
        test_values = [
            42,  # int
            3.14,  # float
            "string",  # str
            b"bytes",  # bytes
            (1, 2, 3),  # tuple
            frozenset([1, 2, 3]),  # frozenset
        ]

        for value in test_values:
            # Should not raise exception
            secure_clear_variable(value)

    def test_memory_clearing_with_flask_app_context(self):
        """Test memory clearing with Flask application context."""
        from flask import Flask

        app = Flask(__name__)

        with app.app_context():
            key = Mock()
            key._private_key = "sensitive"

            # Should use Flask's current_app for logging
            secure_clear_variable(key)

        # Should complete without error

    def test_secure_key_manager_initialization_without_flask_app(self):
        """Test SecureKeyManager initialization without Flask app context."""
        key = ed25519.Ed25519PrivateKey.generate()

        # Ensure no Flask app context
        with patch('app.utils.secure_memory.current_app', None):
            manager = SecureKeyManager(key)

        assert manager._key is key
        assert not manager._cleared

    def test_secure_key_manager_context_manager(self):
        """Test SecureKeyManager as context manager - covers lines 192-198."""
        key = ed25519.Ed25519PrivateKey.generate()
        cert = Mock()

        manager = SecureKeyManager(key, cert)

        # Test context manager entry and exit
        with manager as mgr:
            assert mgr is manager
            assert mgr.key is key
            assert mgr.cert is cert

        # After context, should be cleared
        assert manager._cleared
        with pytest.raises(RuntimeError, match="Key has been cleared"):
            _ = manager.key


class TestSecureZeroMemory:
    """Test the secure_zero_memory function coverage."""

    def test_secure_zero_memory_unix_systems(self):
        """Test secure_zero_memory on Unix-like systems - covers lines 76-85."""
        import ctypes
        import sys

        # Mock Unix-like system
        with patch('sys.platform', 'linux'):
            with patch('ctypes.memset') as mock_memset:
                # Should call ctypes.memset for Unix
                secure_zero_memory(12345, 1024)
                mock_memset.assert_called_once_with(12345, 0, 1024)

    def test_secure_zero_memory_windows_path_coverage(self):
        """Test secure_zero_memory Windows path - covers line 79."""
        import sys

        # We just need to cover the Windows branch for completeness
        # even though it won't run on Windows in production
        with patch('sys.platform', 'win32'):
            with patch('ctypes.windll', create=True) as mock_windll:
                mock_windll.kernel32.RtlSecureZeroMemory = Mock()
                secure_zero_memory(12345, 1024)
                mock_windll.kernel32.RtlSecureZeroMemory.assert_called_once_with(12345, 1024)

    def test_secure_zero_memory_exception_handling(self):
        """Test secure_zero_memory exception handling - covers lines 83-85."""
        import ctypes

        # Mock ctypes.memset to raise exception
        with patch('ctypes.memset', side_effect=Exception("Memory access error")):
            # Should not raise exception - silently fail
            secure_zero_memory(12345, 1024)

        # Should complete without error


class TestCreateSecureKeyManager:
    """Test the create_secure_key_manager function coverage."""

    def test_create_secure_key_manager_with_tuple_return(self):
        """Test create_secure_key_manager with tuple return - covers lines 212-217."""
        mock_key = Mock()
        mock_cert = Mock()

        def mock_loader():
            return (mock_key, mock_cert)

        manager = create_secure_key_manager(mock_loader)

        assert isinstance(manager, SecureKeyManager)
        assert manager._key is mock_key
        assert manager._cert is mock_cert

    def test_create_secure_key_manager_with_single_return(self):
        """Test create_secure_key_manager with single key return - covers lines 216-217."""
        mock_key = Mock()

        def mock_loader():
            return mock_key

        manager = create_secure_key_manager(mock_loader)

        assert isinstance(manager, SecureKeyManager)
        assert manager._key is mock_key
        assert manager._cert is None

    def test_create_secure_key_manager_with_args_and_kwargs(self):
        """Test create_secure_key_manager with arguments - covers line 212."""
        mock_key = Mock()

        def mock_loader(arg1, arg2, kwarg1=None):
            assert arg1 == "test_arg1"
            assert arg2 == "test_arg2"
            assert kwarg1 == "test_kwarg"
            return mock_key

        manager = create_secure_key_manager(mock_loader, "test_arg1", "test_arg2", kwarg1="test_kwarg")

        assert isinstance(manager, SecureKeyManager)
        assert manager._key is mock_key


class TestSecureMemoryAdditionalCoverage:
    """Additional tests to cover remaining missing lines."""

    def test_secure_clear_variable_with_bytes_attributes(self):
        """Test clearing variable with bytes attributes - covers lines 46-47."""
        class MockKeyWithBytes:
            def __init__(self):
                self.key_data = b"secret_key_data"
                self._private_bytes = b"private_data"
                self.normal_attr = 123

        mock_key = MockKeyWithBytes()

        secure_clear_variable(mock_key)

        # Bytes attributes should be set to None (can't modify immutable bytes)
        assert mock_key.key_data is None
        assert mock_key._private_bytes is None
        assert mock_key.normal_attr == 123  # Should not be cleared

    def test_secure_clear_variable_with_cert_clearing(self):
        """Test secure key context with cert clearing - covers lines 132-134."""
        mock_key = Mock()
        mock_cert = Mock()

        def mock_loader():
            return (mock_key, mock_cert)

        with secure_key_context(mock_loader) as result:
            key, cert = result
            assert key is mock_key
            assert cert is mock_cert

        # Both key and cert should be cleared

    def test_secure_key_context_with_flask_logging(self, app_context):
        """Test secure key context with Flask logging - covers lines 121, 129."""
        mock_key = Mock()
        mock_cert = Mock()

        def mock_loader():
            return (mock_key, mock_cert)

        with secure_key_context(mock_loader) as result:
            key, cert = result
            assert key is mock_key
            assert cert is mock_cert

    def test_secure_key_manager_flask_logging_coverage(self, app_context):
        """Test SecureKeyManager Flask logging - covers lines 161, 179."""
        key = ed25519.Ed25519PrivateKey.generate()

        # Create manager - should log initialization (line 161)
        manager = SecureKeyManager(key)

        # Clear manually - should log clearing (line 179)
        manager.clear()


class TestSecureMemoryFlaskContextCoverage:
    """Test secure memory functions with Flask context to achieve 100% coverage."""

    def test_secure_clear_variable_with_flask_context(self, app_context):
        """Test secure_clear_variable with Flask context - covers lines 55-58."""
        mock_var = Mock()
        mock_var._private_key = "secret"
        mock_var.test_attr = bytearray(b"test_data")

        # Create a partial setattr that fails only for specific attributes
        original_setattr = setattr
        def selective_failing_setattr(obj, name, value):
            if name == "test_attr" and hasattr(obj, 'test_attr'):
                raise RuntimeError("Cannot set test_attr")
            return original_setattr(obj, name, value)

        with patch('builtins.setattr', side_effect=selective_failing_setattr):
            secure_clear_variable(mock_var)
            # Should complete without raising exception due to error handling

    def test_secure_key_context_flask_logging(self, app_context):
        """Test secure_key_context with Flask logging - covers lines 121, 129."""
        mock_key = Mock()
        mock_cert = Mock()

        def mock_loader():
            return (mock_key, mock_cert)

        with secure_key_context(mock_loader) as result:
            key, cert = result
            assert key is mock_key
            assert cert is mock_cert

    def test_secure_key_manager_flask_initialization_logging(self, app_context):
        """Test SecureKeyManager Flask initialization logging - covers line 161."""
        key = ed25519.Ed25519PrivateKey.generate()
        manager = SecureKeyManager(key)

        assert manager._key is key
        assert not manager._cleared

    def test_secure_key_manager_flask_clear_logging(self, app_context):
        """Test SecureKeyManager Flask clear logging - covers line 179."""
        key = ed25519.Ed25519PrivateKey.generate()
        manager = SecureKeyManager(key)

        # Clear manually to trigger Flask logging
        manager.clear()

        assert manager._cleared
        assert manager._key is None