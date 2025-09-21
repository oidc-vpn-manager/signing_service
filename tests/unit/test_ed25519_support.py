"""
Tests for Ed25519 cryptographic support in the signing service.
"""

import pytest
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ed25519, ed448, rsa, ec
from cryptography.hazmat.primitives import serialization, hashes

from app.utils.ca_core import sign_csr


class TestEd25519Support:
    """Test cases for Ed25519 key support in certificate signing."""

    def test_sign_csr_with_ed25519_issuer_key(self, app):
        """Test signing a CSR with an Ed25519 issuer key."""
        # Generate Ed25519 issuer key and certificate
        issuer_key = ed25519.Ed25519PrivateKey.generate()
        issuer_subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Test Ed25519 Issuer")
        ])

        issuer_cert = x509.CertificateBuilder().subject_name(
            issuer_subject
        ).issuer_name(
            issuer_subject  # Self-signed for test
        ).public_key(
            issuer_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(issuer_key, None)  # Ed25519 uses None for algorithm

        # Generate client key and CSR
        client_key = ed25519.Ed25519PrivateKey.generate()
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Ed25519 Client")])
        ).sign(client_key, None)

        # Sign the CSR with Ed25519 issuer (within app context)
        with app.app_context():
            signed_cert = sign_csr(csr, issuer_cert, issuer_key)

        # Verify the signed certificate
        assert signed_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Ed25519 Client"
        assert signed_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Test Ed25519 Issuer"
        assert isinstance(signed_cert.public_key(), ed25519.Ed25519PublicKey)

    def test_sign_csr_with_ed448_issuer_key(self, app):
        """Test signing a CSR with an Ed448 issuer key."""
        # Generate Ed448 issuer key and certificate
        issuer_key = ed448.Ed448PrivateKey.generate()
        issuer_subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Test Ed448 Issuer")
        ])

        issuer_cert = x509.CertificateBuilder().subject_name(
            issuer_subject
        ).issuer_name(
            issuer_subject  # Self-signed for test
        ).public_key(
            issuer_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(issuer_key, None)  # Ed448 uses None for algorithm

        # Generate client key and CSR
        client_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Ed448 Client")])
        ).sign(client_key, hashes.SHA256())

        # Sign the CSR with Ed448 issuer (within app context)
        with app.app_context():
            signed_cert = sign_csr(csr, issuer_cert, issuer_key)

        # Verify the signed certificate
        assert signed_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Ed448 Client"
        assert signed_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Test Ed448 Issuer"
        assert isinstance(signed_cert.public_key(), rsa.RSAPublicKey)

    def test_sign_csr_with_ecdsa_issuer_key(self, app):
        """Test signing a CSR with an ECDSA issuer key."""
        # Generate ECDSA issuer key and certificate
        issuer_key = ec.generate_private_key(ec.SECP256R1())
        issuer_subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Test ECDSA Issuer")
        ])

        issuer_cert = x509.CertificateBuilder().subject_name(
            issuer_subject
        ).issuer_name(
            issuer_subject  # Self-signed for test
        ).public_key(
            issuer_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(issuer_key, hashes.SHA256())

        # Generate client key and CSR
        client_key = ed25519.Ed25519PrivateKey.generate()
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ECDSA Client")])
        ).sign(client_key, None)

        # Sign the CSR with ECDSA issuer (within app context)
        with app.app_context():
            signed_cert = sign_csr(csr, issuer_cert, issuer_key)

        # Verify the signed certificate
        assert signed_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "ECDSA Client"
        assert signed_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Test ECDSA Issuer"
        assert isinstance(signed_cert.public_key(), ed25519.Ed25519PublicKey)

    def test_mixed_key_types_cross_compatibility(self, app):
        """Test that different key types can sign certificates for each other."""
        key_types = [
            ("Ed25519", ed25519.Ed25519PrivateKey.generate(), None),
            ("Ed448", ed448.Ed448PrivateKey.generate(), None),
            ("RSA-2048", rsa.generate_private_key(65537, 2048), hashes.SHA256()),
            ("ECDSA-P256", ec.generate_private_key(ec.SECP256R1()), hashes.SHA256()),
        ]

        certificates = {}

        # Create self-signed certificates for each key type
        for name, key, algorithm in key_types:
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Test {name} CA")])

            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                subject  # Self-signed
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.now(timezone.utc)
            ).not_valid_after(
                datetime.now(timezone.utc) + timedelta(days=365)
            ).sign(key, algorithm)

            certificates[name] = (key, cert, algorithm)

        # Test cross-compatibility: each issuer signs for each client type
        for issuer_name, (issuer_key, issuer_cert, issuer_alg) in certificates.items():
            for client_name, (client_key, _, client_alg) in certificates.items():
                # Create CSR with client key
                csr = x509.CertificateSigningRequestBuilder().subject_name(
                    x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{issuer_name}-signs-{client_name}")])
                ).sign(client_key, client_alg)

                # Sign with issuer key (within app context)
                with app.app_context():
                    signed_cert = sign_csr(csr, issuer_cert, issuer_key)

                # Verify the certificate
                assert signed_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == f"{issuer_name}-signs-{client_name}"
                assert signed_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == f"Test {issuer_name} CA"

                # Verify the public key matches the client's public key
                assert signed_cert.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ) == client_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )

    def test_ed25519_certificate_attributes(self, app):
        """Test that Ed25519 certificates have proper attributes."""
        # Generate Ed25519 CA
        ca_key = ed25519.Ed25519PrivateKey.generate()
        ca_subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Ed25519 Test CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organization"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US")
        ])

        ca_cert = x509.CertificateBuilder().subject_name(
            ca_subject
        ).issuer_name(
            ca_subject
        ).public_key(
            ca_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(ca_key, None)

        # Generate client key and CSR with multiple attributes
        client_key = ed25519.Ed25519PrivateKey.generate()
        client_subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "client.example.com"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Client Organization"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "IT Department"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco")
        ])

        csr = x509.CertificateSigningRequestBuilder().subject_name(
            client_subject
        ).sign(client_key, None)

        # Sign the CSR (within app context)
        with app.app_context():
            signed_cert = sign_csr(csr, ca_cert, ca_key)

        # Verify all subject attributes are preserved
        subject_attrs = {attr.oid: attr.value for attr in signed_cert.subject}
        assert subject_attrs[NameOID.COMMON_NAME] == "client.example.com"
        assert subject_attrs[NameOID.ORGANIZATION_NAME] == "Client Organization"
        assert subject_attrs[NameOID.ORGANIZATIONAL_UNIT_NAME] == "IT Department"
        assert subject_attrs[NameOID.COUNTRY_NAME] == "US"
        assert subject_attrs[NameOID.STATE_OR_PROVINCE_NAME] == "California"
        assert subject_attrs[NameOID.LOCALITY_NAME] == "San Francisco"

        # Verify issuer attributes
        issuer_attrs = {attr.oid: attr.value for attr in signed_cert.issuer}
        assert issuer_attrs[NameOID.COMMON_NAME] == "Ed25519 Test CA"
        assert issuer_attrs[NameOID.ORGANIZATION_NAME] == "Test Organization"
        assert issuer_attrs[NameOID.COUNTRY_NAME] == "US"

    def test_ed25519_key_size_and_performance(self):
        """Test Ed25519 key characteristics and performance."""
        # Generate multiple Ed25519 keys to test consistency
        keys = [ed25519.Ed25519PrivateKey.generate() for _ in range(10)]

        for i, key in enumerate(keys):
            # Verify key can be serialized
            private_pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            public_pem = key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Verify key can be loaded back
            loaded_key = serialization.load_pem_private_key(private_pem, password=None)
            assert isinstance(loaded_key, ed25519.Ed25519PrivateKey)

            # Verify Ed25519 public key size (32 bytes for raw key)
            raw_public_key = key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            assert len(raw_public_key) == 32, f"Ed25519 public key should be 32 bytes, got {len(raw_public_key)}"

            # Create a simple certificate to verify signing works
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Ed25519 Test {i}")])
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                subject
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.now(timezone.utc)
            ).not_valid_after(
                datetime.now(timezone.utc) + timedelta(days=1)
            ).sign(key, None)

            assert cert is not None
            assert isinstance(cert.public_key(), ed25519.Ed25519PublicKey)