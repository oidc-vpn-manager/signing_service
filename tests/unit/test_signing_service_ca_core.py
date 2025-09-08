"""
Unit tests for the ca_core utility in the Signing Service.
"""

import pytest
from flask import Flask
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from datetime import datetime, timezone, timedelta

from app.utils.ca_core import sign_csr

@pytest.fixture
def app():
    """Provides a basic Flask app with default CA config."""
    app = Flask(__name__)
    app.config['END_ENTITY_CERT_LIFESPAN'] = 365
    return app

@pytest.fixture
def dummy_issuer():
    """Generates a self-signed cert and key to act as a dummy CA."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test Intermediate CA"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)
    ).sign(private_key, None)
    
    return private_key, cert

@pytest.fixture
def client_csr():
    """Generates a simple CSR to be signed."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "client1.example.com")])
    )
    return builder.sign(private_key, None)


class TestSignCsr:
    """
    Tests for the sign_csr function.
    """

    def test_signs_csr_successfully(self, app, dummy_issuer, client_csr):
        """
        Tests that a CSR can be signed, creating a valid certificate.
        """
        issuer_key, issuer_cert = dummy_issuer
        
        with app.app_context():
            new_cert = sign_csr(client_csr, issuer_cert, issuer_key)

        assert isinstance(new_cert, x509.Certificate)
        assert new_cert.issuer == issuer_cert.subject
        assert new_cert.subject == client_csr.subject
        
        expected_expiry = datetime.now(timezone.utc) + timedelta(days=365)
        assert new_cert.not_valid_after_utc.date() == expected_expiry.date()


    def test_signs_csr_with_rsa_issuer(self, app, client_csr):
        """
        Tests that the RSA-specific signing logic is covered.
        """
        # Arrange: Create a dummy issuer with an RSA key
        issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test RSA CA")])
        issuer_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            subject
        ).public_key(
            issuer_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(issuer_key, hashes.SHA256())
        
        with app.app_context():
            # Act
            new_cert = sign_csr(client_csr, issuer_cert, issuer_key)

        # Assert
        assert isinstance(new_cert, x509.Certificate)
        assert new_cert.issuer == issuer_cert.subject