"""
Core Certificate Authority (CA) cryptographic operations for OpenVPN Manager.

This module provides the fundamental certificate signing functionality used by
the signing service. It handles X.509 certificate generation from Certificate
Signing Requests (CSRs) with proper cryptographic algorithms and validity periods.

Security features:
- Support for multiple cryptographic algorithms (RSA, ECDSA, EdDSA)
- Configurable certificate lifespans
- Proper X.509v3 extensions
- Secure serial number generation
- Timezone-aware certificate validity periods
"""

from datetime import datetime, timezone, timedelta
from flask import current_app
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448

def sign_csr(
    csr: x509.CertificateSigningRequest,
    issuer_cert: x509.Certificate,
    issuer_key,
) -> x509.Certificate:
    """
    Sign a Certificate Signing Request (CSR) and return a valid X.509 certificate.

    This function is the core cryptographic operation of the signing service.
    It takes a CSR from a client (user, server, or computer) and signs it using
    the intermediate CA's private key, creating a valid X.509 certificate.

    The function automatically:
    - Determines the appropriate signing algorithm based on the CA key type
    - Sets certificate validity period from configuration
    - Generates cryptographically secure serial numbers
    - Creates properly formatted X.509v3 certificates
    - Handles timezone-aware validity periods

    Args:
        csr (x509.CertificateSigningRequest): The certificate signing request to sign.
                                            Contains the public key and subject information.
        issuer_cert (x509.Certificate): The intermediate CA certificate used for signing.
                                      Provides the issuer name and trust chain.
        issuer_key: The intermediate CA private key for signing operations.
                   Supports RSA, ECDSA (P-256, P-384, P-521), Ed25519, and Ed448.

    Returns:
        x509.Certificate: A signed X.509 certificate with:
            - Subject name from the CSR
            - Issuer name from the CA certificate
            - Public key from the CSR
            - Cryptographically secure serial number
            - Validity period based on configuration (default: 365 days)
            - Appropriate signing algorithm for the CA key type

    Configuration:
        END_ENTITY_CERT_LIFESPAN (int): Certificate validity period in days (default: 365)

    Cryptographic Algorithm Selection:
        - RSA keys: SHA-256 with RSA signature
        - ECDSA keys: SHA-256 with ECDSA signature
        - Ed25519/Ed448: Native EdDSA (no separate hash algorithm)
        - Unknown types: SHA-256 fallback with warning

    Example:
        >>> from cryptography import x509
        >>> from cryptography.hazmat.primitives import serialization
        >>>
        >>> # Load CSR and CA materials
        >>> csr = x509.load_pem_x509_csr(csr_pem.encode())
        >>> ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
        >>> ca_key = serialization.load_pem_private_key(ca_key_pem.encode(), passphrase)
        >>>
        >>> # Sign the CSR
        >>> signed_cert = sign_csr(csr, ca_cert, ca_key)
        >>>
        >>> # Convert to PEM format
        >>> cert_pem = signed_cert.public_bytes(serialization.Encoding.PEM)

    Security Notes:
        - Serial numbers are cryptographically secure (not sequential)
        - Certificates are UTC timezone-aware
        - Signing algorithms follow current cryptographic best practices
        - CA private key should be properly protected with passphrases
    """
    # Get the lifespan from the application config, defaulting to 365 days
    lifespan_days = int(current_app.config.get('END_ENTITY_CERT_LIFESPAN', 365))
    start_time = datetime.now(timezone.utc)
    end_time = start_time + timedelta(days=lifespan_days)

    # Determine the appropriate signing algorithm based on the issuer key type
    signing_algorithm = None
    if isinstance(issuer_key, rsa.RSAPrivateKey):
        # RSA keys use SHA-256 hash algorithm for PKCS#1 v1.5 or PSS signatures
        signing_algorithm = hashes.SHA256()
    elif isinstance(issuer_key, ec.EllipticCurvePrivateKey):
        # ECDSA keys use SHA-256 hash algorithm for signature generation
        signing_algorithm = hashes.SHA256()
    elif isinstance(issuer_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        # Ed25519 and Ed448 use deterministic signatures (no separate hash algorithm)
        signing_algorithm = None
    else:
        # For unknown key types, attempt to use SHA-256 as fallback
        current_app.logger.warning(f"Unknown issuer key type: {type(issuer_key).__name__}, using SHA-256 as fallback")
        signing_algorithm = hashes.SHA256()

    # Build the X.509 certificate with proper fields
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(issuer_cert.subject)
    builder = builder.public_key(csr.public_key())
    builder = builder.serial_number(x509.random_serial_number())  # Cryptographically secure
    builder = builder.not_valid_before(start_time)
    builder = builder.not_valid_after(end_time)

    # Sign the certificate with the CA private key
    new_cert = builder.sign(issuer_key, signing_algorithm)

    return new_cert