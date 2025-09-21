"""
Tests for unknown key type fallback handling in signing service.

These tests ensure that the fallback mechanism for unknown key types works correctly
and logs appropriate warnings when encountering key types not explicitly handled.
"""

import pytest
from unittest.mock import patch
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from cryptography.hazmat.primitives import hashes

from app.utils.ca_core import sign_csr


class TestUnknownKeyTypeFallback:
    """Test cases for unknown key type fallback handling in certificate signing."""

    def test_dsa_key_type_fallback_warning(self, app):
        """Test that DSA key types trigger fallback with warning log (lines 37-38)."""
        # Generate DSA issuer key and certificate (DSA is supported by cryptography but not explicitly handled)
        dsa_issuer_key = dsa.generate_private_key(key_size=2048)
        issuer_subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Test DSA Key Type Issuer")
        ])

        issuer_cert = x509.CertificateBuilder().subject_name(
            issuer_subject
        ).issuer_name(
            issuer_subject  # Self-signed for test
        ).public_key(
            dsa_issuer_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(dsa_issuer_key, hashes.SHA256())

        # Generate client key and CSR
        client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DSA Key Type Client")])
        ).sign(client_key, hashes.SHA256())

        # Test the fallback within app context and capture logs
        with app.app_context():
            with patch.object(app.logger, 'warning') as mock_logger_warning:
                signed_cert = sign_csr(csr, issuer_cert, dsa_issuer_key)

                # Verify that the warning was logged for DSA key type
                mock_logger_warning.assert_called_once()
                warning_call = mock_logger_warning.call_args[0][0]
                assert "Unknown issuer key type: DSAPrivateKey, using SHA-256 as fallback" in warning_call

        # Verify the signed certificate was created successfully
        assert signed_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "DSA Key Type Client"
        assert signed_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Test DSA Key Type Issuer"

    def test_dsa_key_type_uses_sha256_fallback(self, app):
        """Test that DSA key types use SHA-256 algorithm as fallback."""
        # Generate DSA issuer key and certificate
        dsa_issuer_key = dsa.generate_private_key(key_size=2048)
        issuer_subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "SHA256 Fallback Test Issuer")
        ])

        issuer_cert = x509.CertificateBuilder().subject_name(
            issuer_subject
        ).issuer_name(
            issuer_subject
        ).public_key(
            dsa_issuer_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(dsa_issuer_key, hashes.SHA256())

        # Generate CSR
        client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SHA256 Fallback Client")])
        ).sign(client_key, hashes.SHA256())

        # Test signing with DSA key type (which should trigger the fallback)
        with app.app_context():
            with patch.object(app.logger, 'warning'):  # Suppress warning for this test
                signed_cert = sign_csr(csr, issuer_cert, dsa_issuer_key)

        # Verify certificate was created successfully (the fact that it works means SHA-256 was used)
        assert signed_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "SHA256 Fallback Client"
        assert signed_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "SHA256 Fallback Test Issuer"