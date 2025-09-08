"""
Core Certificate Authority (CA) function for signing.
"""

from datetime import datetime, timezone, timedelta
from flask import current_app
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

def sign_csr(
    csr: x509.CertificateSigningRequest,
    issuer_cert: x509.Certificate,
    issuer_key,
) -> x509.Certificate:
    """
    Signs a Certificate Signing Request (CSR) with an issuer's key and certificate.
    """
    # Get the lifespan from the application config, defaulting to 365 days
    lifespan_days = int(current_app.config.get('END_ENTITY_CERT_LIFESPAN', 365))
    start_time = datetime.now(timezone.utc)
    end_time = start_time + timedelta(days=lifespan_days)

    signing_algorithm = None
    if isinstance(issuer_key, rsa.RSAPrivateKey):
        signing_algorithm = hashes.SHA256()

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(issuer_cert.subject)
    builder = builder.public_key(csr.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(start_time)
    builder = builder.not_valid_after(end_time)
    
    new_cert = builder.sign(issuer_key, signing_algorithm)

    return new_cert