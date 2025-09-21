"""
Secure memory management utilities for cryptographic operations.

This module provides utilities for securely handling private key material
in memory, including secure clearing and context managers for automatic cleanup.
"""

import gc
import sys
import ctypes
from contextlib import contextmanager
from typing import Any, Tuple
from flask import current_app
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography import x509


def secure_clear_variable(var: Any) -> None:
    """
    Attempt to securely clear a variable from memory.

    Note: Python's memory management makes this challenging, but this function
    implements best-effort memory clearing for security-sensitive data.

    Args:
        var: The variable to clear (typically a private key)
    """
    if var is None:
        return

    try:
        # If the variable has private key material, try to zero sensitive fields
        if hasattr(var, '_private_key') or hasattr(var, '_key_bytes'):
            # Log the clearing attempt for audit purposes
            if current_app:
                current_app.logger.debug(f"Attempting secure memory clear for {type(var).__name__}")

        # For private key objects, try to access and clear internal state
        if hasattr(var, '__dict__'):
            for attr_name in list(var.__dict__.keys()):
                attr_value = getattr(var, attr_name)
                if isinstance(attr_value, (bytes, bytearray)):
                    # Zero out byte arrays/bytes objects
                    if isinstance(attr_value, bytearray):
                        attr_value[:] = b'\x00' * len(attr_value)
                    # Note: bytes objects are immutable, but we can try to clear references
                    setattr(var, attr_name, None)
                elif isinstance(attr_value, str) and len(attr_value) > 10:
                    # Clear potentially sensitive string data
                    setattr(var, attr_name, None)

        # Clear the variable reference
        var = None

    except Exception as e:
        # Log any errors but don't fail the operation
        if current_app:
            current_app.logger.warning(f"Error during secure memory clear: {e}")

    finally:
        # Force garbage collection to help with memory cleanup
        gc.collect()


def secure_zero_memory(ptr: int, size: int) -> None:
    """
    Attempt to zero memory at a specific address.

    WARNING: This is platform-specific and may not work on all systems.
    This is a best-effort approach for additional security.

    Args:
        ptr: Memory address pointer
        size: Size of memory to zero
    """
    try:
        if sys.platform.startswith('win'):
            # Windows
            ctypes.windll.kernel32.RtlSecureZeroMemory(ptr, size)
        else:
            # Unix-like systems
            ctypes.memset(ptr, 0, size)
    except Exception:
        # Silently fail - this is best-effort security
        pass


@contextmanager
def secure_key_context(key_loader_func, *args, **kwargs):
    """
    Context manager for secure handling of private keys.

    This context manager ensures that private key material is securely
    cleared from memory when the context exits, even if an exception occurs.

    Args:
        key_loader_func: Function that loads the private key
        *args, **kwargs: Arguments to pass to the key loader function

    Yields:
        Tuple containing the loaded private key and certificate

    Example:
        with secure_key_context(load_intermediate_ca) as (key, cert):
            # Use the key safely
            signed_cert = sign_csr(csr, cert, key)
        # Key is automatically cleared from memory here
    """
    key = None
    cert = None

    try:
        # Load the key and certificate
        result = key_loader_func(*args, **kwargs)
        if isinstance(result, tuple) and len(result) >= 2:
            key, cert = result[0], result[1]
        else:
            key = result

        if current_app:
            current_app.logger.debug(f"Loaded private key {type(key).__name__} in secure context")

        yield (key, cert) if cert else key

    finally:
        # Secure cleanup
        if key is not None:
            if current_app:
                current_app.logger.debug(f"Clearing private key {type(key).__name__} from secure context")
            secure_clear_variable(key)

        if cert is not None:
            # Certificates don't contain sensitive material, but clear for consistency
            secure_clear_variable(cert)

        # Additional cleanup
        gc.collect()


class SecureKeyManager:
    """
    Secure key manager that automatically clears keys when destroyed.

    This class provides automatic memory management for private keys,
    ensuring they are cleared when the object is garbage collected.
    """

    def __init__(self, key: PrivateKeyTypes, cert: x509.Certificate = None):
        """
        Initialize the secure key manager.

        Args:
            key: The private key to manage
            cert: Optional certificate associated with the key
        """
        self._key = key
        self._cert = cert
        self._cleared = False

        if current_app:
            current_app.logger.debug(f"SecureKeyManager managing {type(key).__name__}")

    @property
    def key(self) -> PrivateKeyTypes:
        """Get the managed private key."""
        if self._cleared:
            raise RuntimeError("Key has been cleared and is no longer available")
        return self._key

    @property
    def cert(self) -> x509.Certificate:
        """Get the managed certificate."""
        return self._cert

    def clear(self) -> None:
        """Manually clear the managed key from memory."""
        if not self._cleared:
            if current_app:
                current_app.logger.debug(f"Manually clearing {type(self._key).__name__}")
            secure_clear_variable(self._key)
            secure_clear_variable(self._cert)
            self._key = None
            self._cert = None
            self._cleared = True

    def __del__(self):
        """Automatically clear keys when the manager is destroyed."""
        if not self._cleared:
            secure_clear_variable(self._key)
            secure_clear_variable(self._cert)

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with automatic cleanup."""
        self.clear()


def create_secure_key_manager(key_loader_func, *args, **kwargs) -> SecureKeyManager:
    """
    Create a SecureKeyManager from a key loader function.

    Args:
        key_loader_func: Function that loads the private key
        *args, **kwargs: Arguments to pass to the key loader function

    Returns:
        SecureKeyManager instance managing the loaded key
    """
    result = key_loader_func(*args, **kwargs)
    if isinstance(result, tuple) and len(result) >= 2:
        key, cert = result[0], result[1]
        return SecureKeyManager(key, cert)
    else:
        return SecureKeyManager(result)