"""
Unit tests for TLS setup utilities.

Tests cover snakeoil certificate generation, certificate chain assembly,
and Gunicorn TLS configuration with comprehensive security validation.
"""

import ipaddress
import os
import tempfile
import pytest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.utils.tls_setup import (
    _is_tls_enabled,
    _parse_san_entry,
    generate_snakeoil_cert,
    assemble_cert_chain,
    configure_tls_for_gunicorn,
)


class TestIsTlsEnabled:
    """Tests for _is_tls_enabled."""

    @pytest.mark.parametrize("value", ['true', 'True', 'TRUE', 'yes', 'on', '1'])
    def test_enabled_values(self, value):
        """TLS is enabled for various truthy strings."""
        with patch.dict(os.environ, {'ENABLE_APPLICATION_TLS': value}):
            assert _is_tls_enabled() is True

    @pytest.mark.parametrize("value", ['false', 'False', 'FALSE', 'no', 'off', '0'])
    def test_disabled_values(self, value):
        """TLS is disabled for various falsy strings."""
        with patch.dict(os.environ, {'ENABLE_APPLICATION_TLS': value}):
            assert _is_tls_enabled() is False

    def test_default_is_enabled(self):
        """TLS defaults to enabled when env var is not set."""
        with patch.dict(os.environ, {}, clear=True):
            assert _is_tls_enabled() is True

    def test_unknown_value_treated_as_enabled(self):
        """Unknown values are treated as enabled (defense-in-depth)."""
        with patch.dict(os.environ, {'ENABLE_APPLICATION_TLS': 'maybe'}):
            assert _is_tls_enabled() is True

    def test_whitespace_trimmed(self):
        """Whitespace around the value is trimmed."""
        with patch.dict(os.environ, {'ENABLE_APPLICATION_TLS': '  false  '}):
            assert _is_tls_enabled() is False


class TestParseSanEntry:
    """Tests for _parse_san_entry."""

    def test_dns_name(self):
        """Parses a hostname as a DNS SAN."""
        result = _parse_san_entry('example.com')
        assert isinstance(result, x509.DNSName)
        assert result.value == 'example.com'

    def test_ipv4_address(self):
        """Parses an IPv4 address as an IP SAN."""
        result = _parse_san_entry('192.168.1.1')
        assert isinstance(result, x509.IPAddress)
        assert result.value == ipaddress.ip_address('192.168.1.1')

    def test_ipv6_address(self):
        """Parses an IPv6 address as an IP SAN."""
        result = _parse_san_entry('::1')
        assert isinstance(result, x509.IPAddress)
        assert result.value == ipaddress.ip_address('::1')

    def test_whitespace_stripped(self):
        """Leading/trailing whitespace is stripped."""
        result = _parse_san_entry('  example.com  ')
        assert isinstance(result, x509.DNSName)
        assert result.value == 'example.com'

    def test_localhost(self):
        """Parses 'localhost' as a DNS name."""
        result = _parse_san_entry('localhost')
        assert isinstance(result, x509.DNSName)
        assert result.value == 'localhost'

    def test_ipv4_loopback(self):
        """Parses 127.0.0.1 as an IP address."""
        result = _parse_san_entry('127.0.0.1')
        assert isinstance(result, x509.IPAddress)
        assert result.value == ipaddress.ip_address('127.0.0.1')


class TestGenerateSnakeoilCert:
    """Tests for generate_snakeoil_cert."""

    def test_generates_cert_and_key_files(self, tmp_path):
        """Generates both certificate and key files."""
        cert_path = str(tmp_path / 'cert.pem')
        key_path = str(tmp_path / 'key.pem')

        result = generate_snakeoil_cert(cert_path, key_path, cn='test-host')

        assert result == (cert_path, key_path)
        assert os.path.isfile(cert_path)
        assert os.path.isfile(key_path)

    def test_cert_is_valid_pem(self, tmp_path):
        """Generated certificate is valid PEM that can be parsed."""
        cert_path = str(tmp_path / 'cert.pem')
        key_path = str(tmp_path / 'key.pem')

        generate_snakeoil_cert(cert_path, key_path, cn='test-host')

        with open(cert_path, 'rb') as f:
            cert_data = f.read()
        assert cert_data.startswith(b'-----BEGIN CERTIFICATE-----')
        cert = x509.load_pem_x509_certificate(cert_data)
        assert cert is not None

    def test_key_is_valid_pem(self, tmp_path):
        """Generated key is valid PEM that can be parsed."""
        cert_path = str(tmp_path / 'cert.pem')
        key_path = str(tmp_path / 'key.pem')

        generate_snakeoil_cert(cert_path, key_path, cn='test-host')

        with open(key_path, 'rb') as f:
            key_data = f.read()
        assert b'-----BEGIN PRIVATE KEY-----' in key_data
        key = serialization.load_pem_private_key(key_data, password=None)
        assert isinstance(key, ec.EllipticCurvePrivateKey)

    def test_custom_cn_in_subject(self, tmp_path):
        """Custom CN is reflected in the certificate subject."""
        cert_path = str(tmp_path / 'cert.pem')
        key_path = str(tmp_path / 'key.pem')

        generate_snakeoil_cert(cert_path, key_path, cn='my-custom-cn')

        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())

        cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        assert len(cn_attrs) == 1
        assert cn_attrs[0].value == 'my-custom-cn'

    def test_default_cn_uses_hostname(self, tmp_path):
        """Default CN uses the system hostname."""
        cert_path = str(tmp_path / 'cert.pem')
        key_path = str(tmp_path / 'key.pem')

        with patch('app.utils.tls_setup.socket.gethostname', return_value='mock-hostname'):
            generate_snakeoil_cert(cert_path, key_path)

        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())

        cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        assert cn_attrs[0].value == 'mock-hostname'

    def test_custom_san_dns_entries(self, tmp_path):
        """Custom DNS SAN entries appear in the certificate."""
        cert_path = str(tmp_path / 'cert.pem')
        key_path = str(tmp_path / 'key.pem')

        generate_snakeoil_cert(
            cert_path, key_path, cn='test',
            san_entries=['example.com', 'www.example.com']
        )

        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())

        san_ext = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)
        assert 'example.com' in dns_names
        assert 'www.example.com' in dns_names

    def test_custom_san_ip_entries(self, tmp_path):
        """Custom IP SAN entries appear in the certificate."""
        cert_path = str(tmp_path / 'cert.pem')
        key_path = str(tmp_path / 'key.pem')

        generate_snakeoil_cert(
            cert_path, key_path, cn='test',
            san_entries=['192.168.1.1', '10.0.0.1']
        )

        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())

        san_ext = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        ip_addrs = san_ext.value.get_values_for_type(x509.IPAddress)
        assert ipaddress.ip_address('192.168.1.1') in ip_addrs
        assert ipaddress.ip_address('10.0.0.1') in ip_addrs

    def test_mixed_san_entries(self, tmp_path):
        """Both DNS and IP SANs can be mixed."""
        cert_path = str(tmp_path / 'cert.pem')
        key_path = str(tmp_path / 'key.pem')

        generate_snakeoil_cert(
            cert_path, key_path, cn='test',
            san_entries=['example.com', '127.0.0.1']
        )

        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())

        san_ext = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)
        ip_addrs = san_ext.value.get_values_for_type(x509.IPAddress)
        assert 'example.com' in dns_names
        assert ipaddress.ip_address('127.0.0.1') in ip_addrs

    def test_default_san_uses_cn(self, tmp_path):
        """Default SAN includes the CN."""
        cert_path = str(tmp_path / 'cert.pem')
        key_path = str(tmp_path / 'key.pem')

        generate_snakeoil_cert(cert_path, key_path, cn='myhost')

        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())

        san_ext = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)
        assert 'myhost' in dns_names

    def test_creates_parent_directories(self, tmp_path):
        """Creates parent directories if they don't exist."""
        cert_path = str(tmp_path / 'nested' / 'dir' / 'cert.pem')
        key_path = str(tmp_path / 'other' / 'nested' / 'key.pem')

        generate_snakeoil_cert(cert_path, key_path, cn='test')

        assert os.path.isfile(cert_path)
        assert os.path.isfile(key_path)

    def test_validity_period_one_year(self, tmp_path):
        """Certificate has approximately 1-year validity period."""
        cert_path = str(tmp_path / 'cert.pem')
        key_path = str(tmp_path / 'key.pem')

        generate_snakeoil_cert(cert_path, key_path, cn='test')

        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())

        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        assert 364 <= delta.days <= 366

    def test_key_is_ec_p256(self, tmp_path):
        """Generated key uses EC P-256 (SECP256R1)."""
        cert_path = str(tmp_path / 'cert.pem')
        key_path = str(tmp_path / 'key.pem')

        generate_snakeoil_cert(cert_path, key_path, cn='test')

        with open(key_path, 'rb') as f:
            key = serialization.load_pem_private_key(f.read(), password=None)

        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert key.key_size == 256

    def test_key_is_not_encrypted(self, tmp_path):
        """Generated key can be loaded without a password."""
        cert_path = str(tmp_path / 'cert.pem')
        key_path = str(tmp_path / 'key.pem')

        generate_snakeoil_cert(cert_path, key_path, cn='test')

        with open(key_path, 'rb') as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        assert key is not None

    def test_basic_constraints_not_ca(self, tmp_path):
        """Certificate has BasicConstraints with CA=False."""
        cert_path = str(tmp_path / 'cert.pem')
        key_path = str(tmp_path / 'key.pem')

        generate_snakeoil_cert(cert_path, key_path, cn='test')

        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())

        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False
        assert bc.critical is True

    def test_self_signed(self, tmp_path):
        """Certificate is self-signed (issuer == subject)."""
        cert_path = str(tmp_path / 'cert.pem')
        key_path = str(tmp_path / 'key.pem')

        generate_snakeoil_cert(cert_path, key_path, cn='test')

        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())

        assert cert.issuer == cert.subject

    def test_logs_warning(self, tmp_path):
        """Logs a warning about snakeoil usage."""
        cert_path = str(tmp_path / 'cert.pem')
        key_path = str(tmp_path / 'key.pem')

        from unittest.mock import patch
        with patch('app.utils.tls_setup.logger') as mock_logger:
            generate_snakeoil_cert(cert_path, key_path, cn='test')

        mock_logger.warning.assert_called_once()
        warning_msg = mock_logger.warning.call_args[0][0] % mock_logger.warning.call_args[0][1:]
        assert 'snakeoil' in warning_msg.lower()
        assert 'DO NOT use in production' in warning_msg


class TestAssembleCertChain:
    """Tests for assemble_cert_chain."""

    def _create_test_certs(self, tmp_path):
        """Helper to create test certificate files."""
        # Generate two certificates for testing
        cert1_path = str(tmp_path / 'server.crt')
        key1_path = str(tmp_path / 'server.key')
        cert2_path = str(tmp_path / 'ca.crt')
        key2_path = str(tmp_path / 'ca.key')

        generate_snakeoil_cert(cert1_path, key1_path, cn='server')
        generate_snakeoil_cert(cert2_path, key2_path, cn='ca')

        return cert1_path, cert2_path

    def test_chain_contains_both_certs(self, tmp_path):
        """Output chain contains both server and CA certificates."""
        server_cert, ca_cert = self._create_test_certs(tmp_path)
        output = str(tmp_path / 'chain.crt')

        assemble_cert_chain(server_cert, ca_cert, output)

        with open(output, 'rb') as f:
            chain_data = f.read()

        # Count certificate boundaries
        cert_count = chain_data.count(b'-----BEGIN CERTIFICATE-----')
        assert cert_count == 2

    def test_server_cert_first_in_chain(self, tmp_path):
        """Server certificate appears before CA certificate in chain."""
        server_cert, ca_cert = self._create_test_certs(tmp_path)
        output = str(tmp_path / 'chain.crt')

        assemble_cert_chain(server_cert, ca_cert, output)

        with open(output, 'rb') as f:
            chain_data = f.read()
        with open(server_cert, 'rb') as f:
            server_data = f.read()
        with open(ca_cert, 'rb') as f:
            ca_data = f.read()

        # Server cert should appear first
        server_pos = chain_data.find(server_data.strip())
        ca_pos = chain_data.find(ca_data.strip())
        assert server_pos < ca_pos

    def test_returns_output_path(self, tmp_path):
        """Returns the output path."""
        server_cert, ca_cert = self._create_test_certs(tmp_path)
        output = str(tmp_path / 'chain.crt')

        result = assemble_cert_chain(server_cert, ca_cert, output)
        assert result == output

    def test_raises_on_missing_server_cert(self, tmp_path):
        """Raises FileNotFoundError if server cert doesn't exist."""
        _, ca_cert = self._create_test_certs(tmp_path)
        with pytest.raises(FileNotFoundError, match="Server certificate"):
            assemble_cert_chain('/nonexistent/cert.pem', ca_cert, str(tmp_path / 'out.crt'))

    def test_raises_on_missing_ca_cert(self, tmp_path):
        """Raises FileNotFoundError if CA cert doesn't exist."""
        server_cert, _ = self._create_test_certs(tmp_path)
        with pytest.raises(FileNotFoundError, match="CA certificate"):
            assemble_cert_chain(server_cert, '/nonexistent/ca.pem', str(tmp_path / 'out.crt'))

    def test_creates_output_parent_dirs(self, tmp_path):
        """Creates parent directories for the output file."""
        server_cert, ca_cert = self._create_test_certs(tmp_path)
        output = str(tmp_path / 'nested' / 'dir' / 'chain.crt')

        assemble_cert_chain(server_cert, ca_cert, output)
        assert os.path.isfile(output)

    def test_handles_cert_without_trailing_newline(self, tmp_path):
        """Handles certificates that don't end with a newline."""
        server_cert, ca_cert = self._create_test_certs(tmp_path)

        # Rewrite server cert without trailing newline
        with open(server_cert, 'rb') as f:
            data = f.read().rstrip(b'\n')
        with open(server_cert, 'wb') as f:
            f.write(data)

        output = str(tmp_path / 'chain.crt')
        assemble_cert_chain(server_cert, ca_cert, output)

        with open(output, 'rb') as f:
            chain_data = f.read()

        cert_count = chain_data.count(b'-----BEGIN CERTIFICATE-----')
        assert cert_count == 2

    def test_certs_individually_parseable_from_chain(self, tmp_path):
        """Each certificate in the chain is individually parseable."""
        server_cert, ca_cert = self._create_test_certs(tmp_path)
        output = str(tmp_path / 'chain.crt')

        assemble_cert_chain(server_cert, ca_cert, output)

        with open(output, 'rb') as f:
            chain_data = f.read()

        # Split on BEGIN markers and parse each
        pem_certs = []
        current = b''
        for line in chain_data.split(b'\n'):
            current += line + b'\n'
            if b'-----END CERTIFICATE-----' in line:
                pem_certs.append(current)
                current = b''

        assert len(pem_certs) == 2
        for pem_cert in pem_certs:
            cert = x509.load_pem_x509_certificate(pem_cert)
            assert cert is not None


class TestConfigureTlsForGunicorn:
    """Tests for configure_tls_for_gunicorn."""

    def test_disabled_returns_none(self):
        """Returns None when TLS is disabled."""
        with patch.dict(os.environ, {'ENABLE_APPLICATION_TLS': 'false'}):
            result = configure_tls_for_gunicorn()
        assert result is None

    def test_enabled_with_existing_certs(self, tmp_path):
        """Returns paths to existing cert/key when they exist."""
        cert_path = str(tmp_path / 'cert.pem')
        key_path = str(tmp_path / 'key.pem')

        # Pre-create cert and key
        generate_snakeoil_cert(cert_path, key_path, cn='test')

        with patch.dict(os.environ, {
            'ENABLE_APPLICATION_TLS': 'true',
            'APPLICATION_TLS_CERT': cert_path,
            'APPLICATION_TLS_KEY': key_path,
            'APPLICATION_CA_CERT': '',
        }):
            result = configure_tls_for_gunicorn()

        assert result is not None
        assert result['certfile'] == cert_path
        assert result['keyfile'] == key_path

    def test_enabled_generates_snakeoil_when_missing(self, tmp_path):
        """Generates snakeoil certs when cert/key files don't exist."""
        cert_path = str(tmp_path / 'tls' / 'cert.pem')
        key_path = str(tmp_path / 'tls' / 'key.pem')

        with patch.dict(os.environ, {
            'ENABLE_APPLICATION_TLS': 'true',
            'APPLICATION_TLS_CERT': cert_path,
            'APPLICATION_TLS_KEY': key_path,
            'APPLICATION_CA_CERT': '',
        }):
            result = configure_tls_for_gunicorn()

        assert result is not None
        assert os.path.isfile(cert_path)
        assert os.path.isfile(key_path)
        assert result['certfile'] == cert_path
        assert result['keyfile'] == key_path

    def test_enabled_with_ca_cert_assembles_chain(self, tmp_path):
        """Assembles certificate chain when CA cert is provided."""
        cert_path = str(tmp_path / 'cert.pem')
        key_path = str(tmp_path / 'key.pem')
        ca_cert_path = str(tmp_path / 'ca.crt')
        chain_dir = str(tmp_path / 'tmp_tls')

        generate_snakeoil_cert(cert_path, key_path, cn='server')
        generate_snakeoil_cert(ca_cert_path, str(tmp_path / 'ca.key'), cn='ca')

        chain_path = os.path.join(chain_dir, 'chain.crt')
        with patch.dict(os.environ, {
            'ENABLE_APPLICATION_TLS': 'true',
            'APPLICATION_TLS_CERT': cert_path,
            'APPLICATION_TLS_KEY': key_path,
            'APPLICATION_CA_CERT': ca_cert_path,
        }):
            with patch('app.utils.tls_setup.assemble_cert_chain',
                       wraps=assemble_cert_chain) as mock_chain:
                result = configure_tls_for_gunicorn()

        assert result is not None
        assert result['keyfile'] == key_path
        # certfile should be the chain path (from /tmp/tls/chain.crt)
        assert 'chain.crt' in result['certfile']

    def test_ca_cert_missing_uses_server_cert_only(self, tmp_path):
        """Falls back to server cert when CA cert path is set but file missing."""
        cert_path = str(tmp_path / 'cert.pem')
        key_path = str(tmp_path / 'key.pem')
        generate_snakeoil_cert(cert_path, key_path, cn='test')

        with patch.dict(os.environ, {
            'ENABLE_APPLICATION_TLS': 'true',
            'APPLICATION_TLS_CERT': cert_path,
            'APPLICATION_TLS_KEY': key_path,
            'APPLICATION_CA_CERT': '/nonexistent/ca.crt',
        }):
            result = configure_tls_for_gunicorn()

        assert result is not None
        assert result['certfile'] == cert_path
        assert result['keyfile'] == key_path

    def test_custom_cn_and_san_passed_to_snakeoil(self, tmp_path):
        """Custom CN and SAN env vars are passed to snakeoil generation."""
        cert_path = str(tmp_path / 'tls' / 'cert.pem')
        key_path = str(tmp_path / 'tls' / 'key.pem')

        with patch.dict(os.environ, {
            'ENABLE_APPLICATION_TLS': 'true',
            'APPLICATION_TLS_CERT': cert_path,
            'APPLICATION_TLS_KEY': key_path,
            'APPLICATION_CA_CERT': '',
            'APPLICATION_TLS_CN': 'custom-cn',
            'APPLICATION_TLS_SAN': 'custom-cn,192.168.1.1',
        }):
            result = configure_tls_for_gunicorn()

        assert result is not None

        # Verify the CN was used
        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
        cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        assert cn_attrs[0].value == 'custom-cn'

        # Verify SANs were used
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)
        ip_addrs = san_ext.value.get_values_for_type(x509.IPAddress)
        assert 'custom-cn' in dns_names
        assert ipaddress.ip_address('192.168.1.1') in ip_addrs

    def test_returns_dict_with_certfile_and_keyfile_keys(self, tmp_path):
        """Returned dict always has 'certfile' and 'keyfile' keys."""
        cert_path = str(tmp_path / 'tls' / 'cert.pem')
        key_path = str(tmp_path / 'tls' / 'key.pem')

        with patch.dict(os.environ, {
            'ENABLE_APPLICATION_TLS': 'true',
            'APPLICATION_TLS_CERT': cert_path,
            'APPLICATION_TLS_KEY': key_path,
            'APPLICATION_CA_CERT': '',
        }):
            result = configure_tls_for_gunicorn()

        assert 'certfile' in result
        assert 'keyfile' in result

    def test_default_is_enabled(self, tmp_path):
        """TLS is enabled by default (defense-in-depth)."""
        cert_path = str(tmp_path / 'tls' / 'cert.pem')
        key_path = str(tmp_path / 'tls' / 'key.pem')

        env = {
            'APPLICATION_TLS_CERT': cert_path,
            'APPLICATION_TLS_KEY': key_path,
            'APPLICATION_CA_CERT': '',
        }
        # Remove ENABLE_APPLICATION_TLS to test default
        with patch.dict(os.environ, env, clear=True):
            result = configure_tls_for_gunicorn()

        assert result is not None

    def test_generates_snakeoil_when_only_key_missing(self, tmp_path):
        """Generates snakeoil when cert exists but key is missing."""
        cert_path = str(tmp_path / 'cert.pem')
        key_path = str(tmp_path / 'key.pem')

        # Create cert only
        generate_snakeoil_cert(cert_path, key_path, cn='test')
        os.unlink(key_path)

        with patch.dict(os.environ, {
            'ENABLE_APPLICATION_TLS': 'true',
            'APPLICATION_TLS_CERT': cert_path,
            'APPLICATION_TLS_KEY': key_path,
            'APPLICATION_CA_CERT': '',
        }):
            result = configure_tls_for_gunicorn()

        assert result is not None
        assert os.path.isfile(key_path)

    def test_empty_san_uses_default(self, tmp_path):
        """Empty APPLICATION_TLS_SAN falls back to hostname default."""
        cert_path = str(tmp_path / 'tls' / 'cert.pem')
        key_path = str(tmp_path / 'tls' / 'key.pem')

        with patch.dict(os.environ, {
            'ENABLE_APPLICATION_TLS': 'true',
            'APPLICATION_TLS_CERT': cert_path,
            'APPLICATION_TLS_KEY': key_path,
            'APPLICATION_CA_CERT': '',
            'APPLICATION_TLS_SAN': '',
        }):
            with patch('app.utils.tls_setup.socket.gethostname', return_value='fallback-host'):
                result = configure_tls_for_gunicorn()

        assert result is not None
        # Should have generated with hostname as SAN
        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)
        assert 'fallback-host' in dns_names
