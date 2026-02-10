"""
TLS setup utilities for application-level TLS.

Handles snakeoil certificate generation, chain assembly (CA + server cert
concatenation for Gunicorn's --certfile), and Gunicorn TLS argument construction.

Environment Variables:
    ENABLE_APPLICATION_TLS: Enable/disable TLS (default: "true")
    APPLICATION_TLS_CERT: Path to TLS certificate (default: "/app/tls/application.crt")
    APPLICATION_TLS_KEY: Path to TLS private key (default: "/app/tls/application.key")
    APPLICATION_CA_CERT: Optional CA certificate for chain serving
    APPLICATION_TLS_CN: Common name for snakeoil cert (default: container hostname)
    APPLICATION_TLS_SAN: Comma-separated SANs for snakeoil cert (default: container hostname)
"""

import os
import ipaddress
import socket
import logging
from datetime import datetime, timezone, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

logger = logging.getLogger(__name__)


def _is_tls_enabled():
    """
    Check whether application TLS is enabled via environment variable.

    Returns:
        bool: True if ENABLE_APPLICATION_TLS is not explicitly disabled.
    """
    false_strings = ['false', 'no', 'off', '0']
    value = os.environ.get('ENABLE_APPLICATION_TLS', 'true').lower().strip()
    return value not in false_strings


def _parse_san_entry(entry):
    """
    Parse a SAN entry string into an x509.GeneralName.

    Attempts to parse as an IP address first; if that fails, treats it as a DNS name.

    Args:
        entry: A string representing a DNS name or IP address.

    Returns:
        x509.GeneralName: Either an x509.IPAddress or x509.DNSName.
    """
    entry = entry.strip()
    try:
        ip = ipaddress.ip_address(entry)
        return x509.IPAddress(ip)
    except ValueError:
        return x509.DNSName(entry)


def generate_snakeoil_cert(cert_path, key_path, cn=None, san_entries=None):
    """
    Generate a self-signed EC P-256 TLS certificate and private key.

    Creates a snakeoil certificate suitable for development/testing. The certificate
    uses ECDSA with P-256 curve and SHA-256, with a 1-year validity period.

    Args:
        cert_path: Filesystem path to write the PEM-encoded certificate.
        key_path: Filesystem path to write the PEM-encoded private key.
        cn: Common name for the certificate subject. Defaults to the container hostname.
        san_entries: List of SAN strings (DNS names or IP addresses). Each entry is
                     automatically parsed as IP or DNS. Defaults to [cn].

    Returns:
        tuple: (cert_path, key_path) of the generated files.

    Raises:
        OSError: If parent directories cannot be created or files cannot be written.

    Security Considerations:
        - The generated key is unencrypted (required by Gunicorn).
        - This certificate is NOT suitable for production use.
        - Uses EC P-256 (SECP256R1) which is NIST-approved and widely supported.
    """
    if cn is None:
        cn = socket.gethostname()

    if san_entries is None:
        san_entries = [cn]

    logger.warning(
        "Generating snakeoil TLS certificate (CN=%s) -- DO NOT use in production",
        cn
    )

    # Generate EC P-256 private key
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Build subject
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    # Parse SAN entries
    san_names = [_parse_san_entry(entry) for entry in san_entries]

    # Build certificate
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(san_names),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    # Create parent directories if needed
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)
    os.makedirs(os.path.dirname(key_path), exist_ok=True)

    # Write certificate
    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # Write private key (unencrypted, required by Gunicorn)
    with open(key_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    logger.info("Snakeoil TLS certificate written to %s and %s", cert_path, key_path)
    return (cert_path, key_path)


def assemble_cert_chain(server_cert_path, ca_cert_path, output_path):
    """
    Assemble a TLS certificate chain by concatenating server and CA certificates.

    Creates a PEM bundle with the server certificate first, followed by the CA
    certificate. This format is required by Gunicorn's --certfile option to serve
    the full certificate chain to clients.

    Args:
        server_cert_path: Path to the PEM-encoded server certificate.
        ca_cert_path: Path to the PEM-encoded CA certificate.
        output_path: Path to write the concatenated chain PEM.

    Returns:
        str: The output_path where the chain was written.

    Raises:
        FileNotFoundError: If server_cert_path or ca_cert_path does not exist.
        OSError: If the output file cannot be written.
    """
    if not os.path.isfile(server_cert_path):
        raise FileNotFoundError(
            f"Server certificate not found: {server_cert_path}"
        )
    if not os.path.isfile(ca_cert_path):
        raise FileNotFoundError(
            f"CA certificate not found: {ca_cert_path}"
        )

    with open(server_cert_path, 'rb') as f:
        server_cert = f.read()
    with open(ca_cert_path, 'rb') as f:
        ca_cert = f.read()

    # Ensure each cert ends with a newline before concatenation
    if not server_cert.endswith(b'\n'):
        server_cert += b'\n'

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, 'wb') as f:
        f.write(server_cert)
        f.write(ca_cert)

    logger.info("Assembled TLS certificate chain at %s", output_path)
    return output_path


def configure_tls_for_gunicorn():
    """
    Configure TLS settings for Gunicorn based on environment variables.

    Reads TLS configuration from environment variables and prepares the certificate
    and key paths for Gunicorn. If TLS is enabled but certificate/key files do not
    exist, generates snakeoil certificates automatically. If a CA certificate is
    provided, assembles a certificate chain for chain serving.

    Returns:
        dict or None: A dictionary with 'certfile' and 'keyfile' keys containing
                      the paths to use with Gunicorn's --certfile and --keyfile
                      options. Returns None if TLS is disabled.

    Environment Variables:
        ENABLE_APPLICATION_TLS: "true" (default) or "false"
        APPLICATION_TLS_CERT: Certificate path (default: "/app/tls/application.crt")
        APPLICATION_TLS_KEY: Key path (default: "/app/tls/application.key")
        APPLICATION_CA_CERT: Optional CA cert path for chain serving
        APPLICATION_TLS_CN: CN for snakeoil cert (default: hostname)
        APPLICATION_TLS_SAN: Comma-separated SANs for snakeoil cert (default: hostname)
    """
    if not _is_tls_enabled():
        logger.info("Application TLS is disabled")
        return None

    cert_path = os.environ.get('APPLICATION_TLS_CERT', '/app/tls/application.crt')
    key_path = os.environ.get('APPLICATION_TLS_KEY', '/app/tls/application.key')
    ca_cert_path = os.environ.get('APPLICATION_CA_CERT', '')

    # Generate snakeoil if cert or key is missing
    if not os.path.isfile(cert_path) or not os.path.isfile(key_path):
        cn = os.environ.get('APPLICATION_TLS_CN', '').strip() or None
        san_raw = os.environ.get('APPLICATION_TLS_SAN', '').strip()
        san_entries = [s.strip() for s in san_raw.split(',') if s.strip()] or None

        generate_snakeoil_cert(cert_path, key_path, cn=cn, san_entries=san_entries)

    # Determine the certfile to use (with or without chain)
    certfile = cert_path
    if ca_cert_path and os.path.isfile(ca_cert_path):
        chain_path = '/tmp/tls/chain.crt'
        certfile = assemble_cert_chain(cert_path, ca_cert_path, chain_path)
        logger.info("Using certificate chain with CA cert for TLS")
    elif ca_cert_path:
        logger.warning(
            "APPLICATION_CA_CERT is set to '%s' but file not found; "
            "using server certificate without chain",
            ca_cert_path
        )

    logger.info("Application TLS enabled: certfile=%s, keyfile=%s", certfile, key_path)
    return {'certfile': certfile, 'keyfile': key_path}
