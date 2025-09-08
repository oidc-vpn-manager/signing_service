"""
Handles loading of cryptographic materials for the Signing Service.
"""

from flask import current_app
from cryptography import x509
from cryptography.hazmat.primitives import serialization

def load_intermediate_ca():
    """
    Loads the Intermediate CA certificate and private key from the paths
    specified in the application config.
    """
    cert_path = current_app.config['INTERMEDIATE_CA_CERTIFICATE_FILE']
    key_path = current_app.config['INTERMEDIATE_CA_KEY_FILE']
    passphrase = current_app.config['INTERMEDIATE_CA_KEY_PASSPHRASE']

    try:
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(
                f.read(),
                password=passphrase.encode('utf-8') if passphrase else None
            )
        return key, cert
    except FileNotFoundError as e:
        raise RuntimeError(f"Could not load Intermediate CA files: {e}")