"""
Comprehensive tests for CRL Generator module.
Focuses on achieving 100% coverage with clean, maintainable tests.
"""

import pytest
import os
import tempfile
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, patch, MagicMock
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.x509.oid import NameOID, ExtensionOID

from app.utils.crl_generator import CRLGenerator


class TestCRLGenerator:
    """Test suite for CRLGenerator class with comprehensive coverage."""
    
    @pytest.fixture
    def rsa_ca_key(self):
        """Generate RSA CA private key for testing."""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
    
    @pytest.fixture
    def ed25519_ca_key(self):
        """Generate Ed25519 CA private key for testing."""
        return ed25519.Ed25519PrivateKey.generate()
    
    @pytest.fixture
    def ca_certificate_with_ski(self, rsa_ca_key):
        """Generate CA certificate with Subject Key Identifier for testing."""
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
        ])
        
        # Generate Subject Key Identifier
        public_key = rsa_ca_key.public_key()
        public_key_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        digest = hashes.Hash(hashes.SHA1())
        digest.update(public_key_der)
        ski = digest.finalize()
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            public_key
        ).serial_number(
            1
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).add_extension(
            x509.SubjectKeyIdentifier(ski),
            critical=False
        ).sign(rsa_ca_key, algorithm=hashes.SHA256())
        
        return cert
    
    @pytest.fixture
    def ca_certificate_without_ski(self, rsa_ca_key):
        """Generate CA certificate without Subject Key Identifier for testing."""
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Test CA No SKI"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            rsa_ca_key.public_key()
        ).serial_number(
            2
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(rsa_ca_key, algorithm=hashes.SHA256())
        
        return cert
    
    @pytest.fixture
    def mock_cert_log(self):
        """Create mock certificate log for testing."""
        # Use a simple dict that also supports attribute access
        mock_log = {
            'serial_number': "1a2b3c4d5e6f",
            'revoked_at': datetime.now(timezone.utc).isoformat(),
            'revocation_reason': "key_compromise"
        }
        return mock_log
    
    @pytest.fixture
    def mock_cert_log_no_reason(self):
        """Create mock certificate log without revocation reason."""
        # Use a simple dict 
        mock_log = {
            'serial_number': "abcdef123456",
            'revoked_at': datetime(2023, 1, 15, 10, 30, 0, tzinfo=timezone.utc).isoformat(),
            'revocation_reason': None
        }
        return mock_log
    
    @pytest.fixture
    def mock_cert_log_naive_datetime(self):
        """Create mock certificate log with naive datetime (no timezone)."""
        # Use a simple dict
        mock_log = {
            'serial_number': "fedcba654321",
            'revoked_at': datetime(2023, 2, 20, 14, 45, 30).isoformat(),  # No timezone in original datetime
            'revocation_reason': "cessation_of_operation"
        }
        return mock_log

    def test_init_default(self):
        """Test CRLGenerator initialization with defaults."""
        generator = CRLGenerator()
        
        assert generator.ca_cert_path is None
        assert generator.ca_key_path is None
        assert generator.ca_key_passphrase is None
        assert generator.issuer_identifier is None
        assert generator._ca_certificate is None
        assert generator._ca_private_key is None

    def test_init_with_paths(self):
        """Test CRLGenerator initialization with file paths."""
        with patch('app.utils.crl_generator.CRLGenerator._load_ca_materials_from_files') as mock_load, \
             patch('app.utils.crl_generator.CRLGenerator._get_next_crl_number', return_value=54321):
            
            generator = CRLGenerator(
                ca_cert_path="/path/to/cert.pem",
                ca_key_path="/path/to/key.pem",
                ca_key_passphrase="test-pass"
            )
            
            assert generator.ca_cert_path == "/path/to/cert.pem"
            assert generator.ca_key_path == "/path/to/key.pem"
            assert generator.ca_key_passphrase == "test-pass"
            mock_load.assert_called_once()

    def test_load_ca_materials_success(self, rsa_ca_key, ca_certificate_with_ski):
        """Test successful loading of CA materials from PEM strings."""
        generator = CRLGenerator()
        
        ca_cert_pem = ca_certificate_with_ski.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        ca_key_pem = rsa_ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        generator.load_ca_materials(ca_cert_pem, ca_key_pem, None)
        
        assert generator._ca_certificate is not None
        assert generator._ca_private_key is not None

    def test_load_ca_materials_with_passphrase(self, rsa_ca_key, ca_certificate_with_ski):
        """Test loading CA materials with encrypted private key."""
        generator = CRLGenerator()
        
        ca_cert_pem = ca_certificate_with_ski.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        passphrase = b"test-passphrase"
        ca_key_pem = rsa_ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
        ).decode('utf-8')
        
        generator.load_ca_materials(ca_cert_pem, ca_key_pem, "test-passphrase")
        
        assert generator._ca_certificate is not None
        assert generator._ca_private_key is not None

    def test_load_ca_materials_invalid_cert(self):
        """Test loading invalid CA certificate."""
        generator = CRLGenerator()
        
        with pytest.raises(ValueError, match="Invalid CA certificate or key"):
            generator.load_ca_materials("invalid-cert-pem", "invalid-key-pem", None)

    def test_load_ca_materials_from_files_existing_files(self, rsa_ca_key, ca_certificate_with_ski):
        """Test loading CA materials from existing files."""
        ca_cert_pem = ca_certificate_with_ski.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        ca_key_pem = rsa_ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        # Create temporary files
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as cert_file, \
             tempfile.NamedTemporaryFile(mode='w', delete=False) as key_file:
            
            cert_file.write(ca_cert_pem)
            key_file.write(ca_key_pem)
            
            cert_path = cert_file.name
            key_path = key_file.name
        
        try:
            generator = CRLGenerator(ca_cert_path=cert_path, ca_key_path=key_path)
            
            assert generator._ca_certificate is not None
            assert generator._ca_private_key is not None
            
        finally:
            os.unlink(cert_path)
            os.unlink(key_path)

    def test_load_ca_materials_from_files_nonexistent_files(self):
        """Test loading CA materials from non-existent files falls back to environment."""
        with patch('app.utils.crl_generator.loadConfigValueFromFileOrEnvironment') as mock_load:
            mock_load.side_effect = ['', '', '']  # Empty values
            
            generator = CRLGenerator(ca_cert_path="/nonexistent", ca_key_path="/nonexistent")
            
            # Should not fail but materials won't be loaded
            assert generator._ca_certificate is None
            assert generator._ca_private_key is None

    def test_load_ca_materials_from_environment(self, rsa_ca_key, ca_certificate_with_ski):
        """Test loading CA materials from environment variables."""
        ca_cert_pem = ca_certificate_with_ski.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        ca_key_pem = rsa_ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        with patch('app.utils.crl_generator.loadConfigValueFromFileOrEnvironment') as mock_load:
            mock_load.side_effect = [ca_cert_pem, ca_key_pem, '']
            
            # Trigger loading by providing paths that don't exist
            generator = CRLGenerator(ca_cert_path="/nonexistent", ca_key_path="/nonexistent")
            
            assert generator._ca_certificate is not None
            assert generator._ca_private_key is not None

    def test_load_ca_materials_from_files_exception_handling(self):
        """Test exception handling in _load_ca_materials_from_files."""
        with patch('app.utils.crl_generator.loadConfigValueFromFileOrEnvironment') as mock_load:
            mock_load.side_effect = Exception("Config error")
            
            # Should not raise exception
            generator = CRLGenerator()
            assert generator._ca_certificate is None

    def test_create_crl_no_ca_materials(self):
        """Test CRL creation without loaded CA materials."""
        generator = CRLGenerator()
        
        with pytest.raises(RuntimeError, match="CA materials not loaded"):
            generator.create_crl([])

    def test_create_crl_empty_list(self, rsa_ca_key, ca_certificate_with_ski):
        """Test CRL creation with empty revoked certificates list."""
        with patch('app.utils.crl_generator.CRLGenerator._get_next_crl_number', return_value=1):
            generator = CRLGenerator()
            
            ca_cert_pem = ca_certificate_with_ski.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            ca_key_pem = rsa_ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            generator.load_ca_materials(ca_cert_pem, ca_key_pem, None)
            
            crl_der = generator.create_crl([])
            
            assert isinstance(crl_der, bytes)
            assert len(crl_der) > 0
            
            # Verify it's a valid CRL
            crl = x509.load_der_x509_crl(crl_der)
            assert len(list(crl)) == 0  # No revoked certificates

    def test_create_crl_with_revoked_certificates(self, rsa_ca_key, ca_certificate_with_ski, mock_cert_log, mock_cert_log_no_reason):
        """Test CRL creation with revoked certificates."""
        with patch('app.utils.crl_generator.CRLGenerator._get_next_crl_number', return_value=2):
            generator = CRLGenerator()
            
            ca_cert_pem = ca_certificate_with_ski.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            ca_key_pem = rsa_ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            generator.load_ca_materials(ca_cert_pem, ca_key_pem, None)
            
            revoked_certs = [mock_cert_log, mock_cert_log_no_reason]
            crl_der = generator.create_crl(revoked_certs, next_update_hours=48)
        
        assert isinstance(crl_der, bytes)
        
        # Verify CRL content
        crl = x509.load_der_x509_crl(crl_der)
        revoked_list = list(crl)
        assert len(revoked_list) == 2
        
        # Check first revoked certificate (with reason)
        assert revoked_list[0].serial_number == int(mock_cert_log['serial_number'], 16)
        # Compare dates by converting to UTC and ignoring microseconds for comparison
        expected_date = datetime.fromisoformat(mock_cert_log['revoked_at']).replace(microsecond=0, second=0, minute=0)
        actual_date = revoked_list[0].revocation_date_utc.replace(microsecond=0, second=0, minute=0)
        assert actual_date.date() == expected_date.date()
        
        # Check second revoked certificate (no reason)
        assert revoked_list[1].serial_number == int(mock_cert_log_no_reason['serial_number'], 16)

    def test_create_crl_naive_datetime_handling(self, rsa_ca_key, ca_certificate_with_ski, mock_cert_log_naive_datetime):
        """Test CRL creation with naive datetime (no timezone info)."""
        with patch('app.utils.crl_generator.CRLGenerator._get_next_crl_number', return_value=3):
            generator = CRLGenerator()
            
            ca_cert_pem = ca_certificate_with_ski.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            ca_key_pem = rsa_ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            generator.load_ca_materials(ca_cert_pem, ca_key_pem, None)
            
            crl_der = generator.create_crl([mock_cert_log_naive_datetime])
        
        # Verify CRL was created successfully
        crl = x509.load_der_x509_crl(crl_der)
        revoked_list = list(crl)
        assert len(revoked_list) == 1

    def test_create_crl_with_ed25519_key(self, ed25519_ca_key):
        """Test CRL creation with Ed25519 private key."""
        # Create certificate with Ed25519 key
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Ed25519 Test CA"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            ed25519_ca_key.public_key()
        ).serial_number(
            1
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(ed25519_ca_key, algorithm=None)  # Ed25519 doesn't use hash algorithm
        
        with patch('app.utils.crl_generator.CRLGenerator._get_next_crl_number', return_value=4):
            generator = CRLGenerator()
            
            ca_cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            ca_key_pem = ed25519_ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            generator.load_ca_materials(ca_cert_pem, ca_key_pem, None)
            
            crl_der = generator.create_crl([])
        
        # Verify CRL was created
        assert isinstance(crl_der, bytes)
        crl = x509.load_der_x509_crl(crl_der)
        assert crl.issuer == cert.subject

    def test_get_current_crl(self, rsa_ca_key, ca_certificate_with_ski):
        """Test getting current CRL from database."""
        generator = CRLGenerator()
        
        ca_cert_pem = ca_certificate_with_ski.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        ca_key_pem = rsa_ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        generator.load_ca_materials(ca_cert_pem, ca_key_pem, None)
        
        # Mock the dynamic import in get_current_crl
        mock_cert_log_class = Mock()
        mock_cert_log_class.get_revoked_certificates.return_value = []
        
        with patch('app.utils.crl_generator.CRLGenerator.create_crl') as mock_create_crl:
            mock_create_crl.return_value = b'test-crl-data'
            
            # Directly mock the import statement in the method
            with patch('builtins.__import__') as mock_import:
                mock_models = Mock()
                mock_models.certificate_log = Mock()
                mock_models.certificate_log.CertificateLog = mock_cert_log_class
                mock_import.return_value = mock_models
                
                crl_der = generator.get_current_crl()
                
                assert isinstance(crl_der, bytes)
                assert crl_der == b'test-crl-data'

    def test_add_crl_extensions_with_ski(self, rsa_ca_key, ca_certificate_with_ski):
        """Test adding CRL extensions when CA has Subject Key Identifier."""
        with patch('app.utils.crl_generator.CRLGenerator._get_next_crl_number', return_value=5):
            generator = CRLGenerator()
            
            ca_cert_pem = ca_certificate_with_ski.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            ca_key_pem = rsa_ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            generator.load_ca_materials(ca_cert_pem, ca_key_pem, None)
            
            crl_der = generator.create_crl([])
        crl = x509.load_der_x509_crl(crl_der)
        
        # Check for CRL Number extension
        crl_number_ext = crl.extensions.get_extension_for_oid(x509.oid.ExtensionOID.CRL_NUMBER)
        assert crl_number_ext is not None
        
        # Check for Authority Key Identifier extension
        aki_ext = crl.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        assert aki_ext is not None

    def test_add_crl_extensions_without_ski(self, rsa_ca_key, ca_certificate_without_ski):
        """Test adding CRL extensions when CA lacks Subject Key Identifier."""
        with patch('app.utils.crl_generator.CRLGenerator._get_next_crl_number', return_value=6):
            generator = CRLGenerator()
            
            ca_cert_pem = ca_certificate_without_ski.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            ca_key_pem = rsa_ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            generator.load_ca_materials(ca_cert_pem, ca_key_pem, None)
            
            crl_der = generator.create_crl([])
        crl = x509.load_der_x509_crl(crl_der)
        
        # Check for CRL Number extension
        crl_number_ext = crl.extensions.get_extension_for_oid(x509.oid.ExtensionOID.CRL_NUMBER)
        assert crl_number_ext is not None
        
        # Check for Authority Key Identifier extension (generated from public key)
        aki_ext = crl.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        assert aki_ext is not None

    def test_map_revocation_reason_valid_reasons(self):
        """Test mapping valid revocation reasons."""
        generator = CRLGenerator()
        
        # Test valid reasons
        assert generator._map_revocation_reason('key_compromise') == x509.ReasonFlags.key_compromise
        assert generator._map_revocation_reason('ca_compromise') == x509.ReasonFlags.ca_compromise
        assert generator._map_revocation_reason('affiliation_changed') == x509.ReasonFlags.affiliation_changed
        assert generator._map_revocation_reason('superseded') == x509.ReasonFlags.superseded
        assert generator._map_revocation_reason('cessation_of_operation') == x509.ReasonFlags.cessation_of_operation
        assert generator._map_revocation_reason('certificate_hold') == x509.ReasonFlags.certificate_hold
        assert generator._map_revocation_reason('remove_from_crl') == x509.ReasonFlags.remove_from_crl
        assert generator._map_revocation_reason('privilege_withdrawn') == x509.ReasonFlags.privilege_withdrawn
        assert generator._map_revocation_reason('aa_compromise') == x509.ReasonFlags.aa_compromise

    def test_map_revocation_reason_invalid_reason(self):
        """Test mapping invalid revocation reason."""
        generator = CRLGenerator()
        
        assert generator._map_revocation_reason('invalid_reason') is None
        assert generator._map_revocation_reason('') is None
        assert generator._map_revocation_reason(None) is None

    def test_get_next_crl_number(self):
        """Test CRL number generation with CT client."""
        with patch('app.utils.crl_generator.get_ct_client') as mock_get_ct_client:
            mock_ct_client = Mock()
            mock_ct_client.get_next_crl_number.return_value = 42
            mock_get_ct_client.return_value = mock_ct_client
            
            generator = CRLGenerator(issuer_identifier="Test CA")
            crl_number = generator._get_next_crl_number()
            
            assert crl_number == 42
            mock_ct_client.get_next_crl_number.assert_called_once_with("Test CA")

    def test_init_with_ca_materials_load_exception(self):
        """Test initialization when CA materials loading fails (lines 99-102)."""
        with patch('app.utils.crl_generator.loadConfigValueFromFileOrEnvironment') as mock_load:
            # Make loading CA materials fail
            mock_load.side_effect = Exception("Failed to load CA materials")
            
            # Should not raise exception - initialization should continue with pass statement
            generator = CRLGenerator(
                ca_cert_path="/path/to/cert.pem",
                ca_key_path="/path/to/key.pem"
            )
            
            # CA materials should not be loaded due to exception
            assert generator._ca_certificate is None
            assert generator._ca_private_key is None

    def test_get_next_crl_number_extract_issuer_from_ca_cert(self, rsa_ca_key, ca_certificate_with_ski):
        """Test extracting issuer identifier from CA certificate (lines 283-291)."""
        generator = CRLGenerator()  # No issuer_identifier set
        
        # Load CA certificate
        ca_cert_pem = ca_certificate_with_ski.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        ca_key_pem = rsa_ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        generator.load_ca_materials(ca_cert_pem, ca_key_pem, None)
        
        with patch('app.utils.crl_generator.get_ct_client') as mock_get_ct_client:
            mock_ct_client = Mock()
            mock_ct_client.get_next_crl_number.return_value = 123
            mock_get_ct_client.return_value = mock_ct_client
            
            # Should extract issuer identifier from CA certificate subject CN
            crl_number = generator._get_next_crl_number()
            
            # Should have extracted "Test CA" from the certificate's subject
            assert generator.issuer_identifier == "Test CA"
            assert crl_number == 123
            mock_ct_client.get_next_crl_number.assert_called_once_with("Test CA")

    def test_get_next_crl_number_no_issuer_no_ca_cert(self):
        """Test error when issuer identifier cannot be determined (line 291)."""
        generator = CRLGenerator()  # No issuer_identifier, no CA cert loaded
        
        # Should raise RuntimeError when issuer can't be determined
        with pytest.raises(RuntimeError, match="Issuer identifier not set and cannot be determined from CA certificate"):
            generator._get_next_crl_number()

    def test_get_next_crl_number_ct_service_fallback(self):
        """Test fallback when CT service is unavailable (lines 296-303)."""
        from app.utils.ct_client import CTClientError
        
        generator = CRLGenerator(issuer_identifier="Test CA")
        
        with patch('app.utils.crl_generator.get_ct_client') as mock_get_ct_client:
            # Make CT client raise an error
            mock_ct_client = Mock()
            mock_ct_client.get_next_crl_number.side_effect = CTClientError("CT service unavailable")
            mock_get_ct_client.return_value = mock_ct_client
            
            with patch('app.utils.crl_generator.datetime') as mock_datetime, \
                 patch('logging.getLogger') as mock_get_logger:
                
                # Mock timestamp
                mock_now = Mock()
                mock_now.timestamp.return_value = 1234567890
                mock_datetime.now.return_value = mock_now
                
                mock_logger = Mock()
                mock_get_logger.return_value = mock_logger
                
                # Should fall back to timestamp-based number
                crl_number = generator._get_next_crl_number()
                
                assert crl_number == 1234567890
                mock_logger.warning.assert_called_once_with("CT service unavailable for CRL number, using fallback: CT service unavailable")

    def test_create_generator_with_config_success(self, rsa_ca_key, ca_certificate_with_ski):
        """Test creating generator with configuration."""
        ca_cert_pem = ca_certificate_with_ski.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        ca_key_pem = rsa_ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        with patch('app.utils.crl_generator.loadConfigValueFromFileOrEnvironment') as mock_load:
            mock_load.side_effect = [ca_cert_pem, ca_key_pem, '']  # No passphrase for unencrypted key
            
            generator = CRLGenerator.create_generator_with_config()
            
            assert generator._ca_certificate is not None
            assert generator._ca_private_key is not None

    def test_create_generator_with_config_no_materials(self):
        """Test creating generator with no configuration materials."""
        with patch('app.utils.crl_generator.loadConfigValueFromFileOrEnvironment') as mock_load:
            mock_load.side_effect = ['', '', '']
            
            generator = CRLGenerator.create_generator_with_config()
            
            assert generator._ca_certificate is None
            assert generator._ca_private_key is None

    def test_crl_number_increment(self, rsa_ca_key, ca_certificate_with_ski, mock_cert_log):
        """Test that CT client is called for each CRL creation."""
        with patch('app.utils.crl_generator.get_ct_client') as mock_get_ct_client:
            mock_ct_client = Mock()
            mock_ct_client.get_next_crl_number.side_effect = [1, 2]  # Return different numbers for each call
            mock_get_ct_client.return_value = mock_ct_client
            
            generator = CRLGenerator(issuer_identifier="Test CA")
            
            ca_cert_pem = ca_certificate_with_ski.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            ca_key_pem = rsa_ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            generator.load_ca_materials(ca_cert_pem, ca_key_pem, None)
            
            # Create two CRLs
            generator.create_crl([])
            generator.create_crl([mock_cert_log])
            
            # Verify CT client was called twice for CRL numbers
            assert mock_ct_client.get_next_crl_number.call_count == 2