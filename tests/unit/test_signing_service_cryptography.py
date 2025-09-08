"""
Unit tests for cryptography utilities in the Signing Service.
"""

import pytest
from flask import Flask
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timezone, timedelta

from app.utils.cryptography import load_intermediate_ca

@pytest.fixture
def app(tmp_path):
    """Provides a Flask app with paths to dummy CA files."""
    app = Flask(__name__)
    app.config['TESTING'] = True

    # Create dummy cert and Ed25519 key files for testing
    key = ed25519.Ed25519PrivateKey.generate()
    cert = x509.CertificateBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    ).issuer_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    ).public_key(key.public_key()).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=1)
    ).sign(key, None) # Ed25519 does not take a hash algorithm

    key_path = tmp_path / "ca.key"
    cert_path = tmp_path / "ca.crt"
    passphrase = "test-password"

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
        ))
    
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    app.config['INTERMEDIATE_CA_KEY_FILE'] = str(key_path)
    app.config['INTERMEDIATE_CA_CERTIFICATE_FILE'] = str(cert_path)
    app.config['INTERMEDIATE_CA_KEY_PASSPHRASE'] = passphrase
    app.config['END_ENTITY_CERT_LIFESPAN'] = 365 # for testing
    
    return app

def test_load_intermediate_ca_success(app):
    """
    Tests that the intermediate CA key and cert are loaded and decrypted successfully.
    """
    with app.app_context():
        key, cert = load_intermediate_ca()

    assert isinstance(key, ed25519.Ed25519PrivateKey)
    assert isinstance(cert, x509.Certificate)

def test_load_intermediate_ca_file_not_found(app):
    """
    Tests that a RuntimeError is raised if a CA file is missing.
    """
    app.config['INTERMEDIATE_CA_KEY_FILE'] = '/non/existent/path/key.pem'
    
    with app.app_context():
        with pytest.raises(RuntimeError, match="Could not load Intermediate CA files"):
            load_intermediate_ca()