import pytest
from flask import Flask
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timezone, timedelta

from app import create_app

@pytest.fixture(scope='function')
def app(tmp_path):
    """
    Creates a new application instance for each test function, including a
    temporary Intermediate CA for the service to load.
    """
    # Create dummy cert and Ed25519 key files for the app to use
    key = ed25519.Ed25519PrivateKey.generate()
    cert = x509.CertificateBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Intermediate CA")])
    ).issuer_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA")])
    ).public_key(key.public_key()).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)
    ).sign(key, None)

    key_path = tmp_path / "intermediate.key"
    cert_path = tmp_path / "intermediate.crt"
    passphrase = "test-password"

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
        ))
    
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # Create the app instance
    app = create_app()
    # Override config to use our temporary files
    app.config.update({
        "TESTING": True,
        "INTERMEDIATE_CA_KEY_FILE": str(key_path),
        "INTERMEDIATE_CA_CERTIFICATE_FILE": str(cert_path),
        "INTERMEDIATE_CA_KEY_PASSPHRASE": passphrase,
        "SIGNING_SERVICE_API_SECRET": "test-api-secret"
    })
    
    yield app

@pytest.fixture(scope='function')
def client(app):
    """A test client for the app."""
    return app.test_client()