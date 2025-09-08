"""
Simplified comprehensive tests for Certificate Transparency Client module.
Focuses on achieving 100% coverage with clean, maintainable tests.
"""

import pytest
import requests
from unittest.mock import Mock, patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timezone, timedelta

from app.utils.certtransparency_client import CTLogClient, CTLogError, log_certificate_to_ct, get_ct_client


class TestCTLogClient:
    """Test suite for CTLogClient class with comprehensive coverage."""
    
    def test_init_and_configuration(self, app):
        """Test client initialization with various configurations."""
        with app.app_context():
            # Test default configuration
            app.config['CERTTRANSPARENCY_SERVICE_URL'] = 'http://ct-service:8080/api/v1'
            app.config['CT_SERVICE_API_SECRET'] = 'default-secret'
            
            client = CTLogClient()
            assert client.base_url == 'http://ct-service:8080/api/v1'
            assert client.api_secret == 'default-secret'
            assert client.timeout == 30
            
            # Test custom configuration
            client2 = CTLogClient(
                base_url='http://custom:9000/api/v1',
                api_secret='custom-secret',
                timeout=60
            )
            assert client2.base_url == 'http://custom:9000/api/v1'
            assert client2.api_secret == 'custom-secret'
            assert client2.timeout == 60
            
            # Test fallback URL
            app.config.pop('CERTTRANSPARENCY_SERVICE_URL', None)
            client3 = CTLogClient()
            assert client3.base_url == 'http://certtransparency:8800/api/v1'

    def test_missing_api_secret_warning(self, app):
        """Test warning when API secret is missing."""
        with app.app_context():
            app.config.pop('CT_SERVICE_API_SECRET', None)
            
            with patch('app.utils.certtransparency_client.current_app.logger') as mock_logger:
                client = CTLogClient()
                assert client.api_secret is None
                mock_logger.warning.assert_called_once()

    def test_log_certificate_success(self, app):
        """Test successful certificate logging with all variations."""
        with app.app_context():
            with patch('requests.post') as mock_post, \
                 patch('app.utils.certtransparency_client.current_app.logger') as mock_logger:
                
                # Setup successful response
                mock_response = Mock()
                mock_response.json.return_value = {
                    'status': 'logged',
                    'certificate': {'fingerprint_sha256': 'abc123'}
                }
                mock_post.return_value = mock_response
                
                client = CTLogClient(api_secret='test-secret')
                
                # Test minimal parameters
                result = client.log_certificate('cert-pem', 'client')
                assert result['status'] == 'logged'
                
                # Verify request parameters
                call_args = mock_post.call_args
                assert call_args[1]['json'] == {
                    'certificate_pem': 'cert-pem',
                    'certificate_type': 'client'
                }
                assert call_args[1]['headers']['X-CT-API-Secret'] == 'test-secret'
                assert call_args[1]['timeout'] == 30
                
                # Test with all parameters
                requester_info = {'ip': '192.168.1.1'}
                result = client.log_certificate(
                    certificate_pem='full-cert-pem',
                    certificate_type='server',
                    certificate_purpose='test-server',
                    requester_info=requester_info,
                    issuing_user_id='user123'
                )
                
                # Verify full payload
                call_args = mock_post.call_args
                expected_payload = {
                    'certificate_pem': 'full-cert-pem',
                    'certificate_type': 'server',
                    'certificate_purpose': 'test-server',
                    'requester_info': requester_info,
                    'issuing_user_id': 'user123'
                }
                assert call_args[1]['json'] == expected_payload

    def test_log_certificate_errors(self, app):
        """Test certificate logging error scenarios."""
        with app.app_context():
            # Test missing API secret
            client = CTLogClient(api_secret=None)
            with pytest.raises(CTLogError, match="CT service API secret not configured"):
                client.log_certificate('cert', 'client')
            
            client = CTLogClient(api_secret='test-secret')
            
            with patch('app.utils.certtransparency_client.current_app.logger') as mock_logger:
                # Test request exception
                with patch('requests.post', side_effect=requests.RequestException("Connection error")):
                    with pytest.raises(CTLogError, match="Failed to communicate with CT service"):
                        client.log_certificate('cert', 'client')
                    mock_logger.error.assert_called()
                
                # Test HTTP error
                mock_response = Mock()
                mock_response.raise_for_status.side_effect = requests.HTTPError("400 Bad Request")
                with patch('requests.post', return_value=mock_response):
                    with pytest.raises(CTLogError, match="Failed to communicate with CT service"):
                        client.log_certificate('cert', 'client')
                
                # Test JSON parsing error
                mock_response = Mock()
                mock_response.json.side_effect = ValueError("Invalid JSON")
                with patch('requests.post', return_value=mock_response):
                    with pytest.raises(CTLogError, match="Invalid response from CT service"):
                        client.log_certificate('cert', 'client')

    def test_get_certificate_by_fingerprint(self, app):
        """Test certificate retrieval functionality."""
        with app.app_context():
            client = CTLogClient(api_secret='test-secret')
            
            # Test missing API secret
            client_no_secret = CTLogClient(api_secret=None)
            with pytest.raises(CTLogError, match="CT service API secret not configured"):
                client_no_secret.get_certificate_by_fingerprint('abc123')
            
            with patch('requests.get') as mock_get, \
                 patch('app.utils.certtransparency_client.current_app.logger') as mock_logger:
                
                # Test successful retrieval
                mock_response = Mock()
                mock_response.json.return_value = {'certificate': {'fingerprint': 'abc123'}}
                mock_get.return_value = mock_response
                
                result = client.get_certificate_by_fingerprint('abc123')
                assert result == {'certificate': {'fingerprint': 'abc123'}}
                
                # Verify request
                call_args = mock_get.call_args
                assert 'abc123' in call_args[0][0]
                assert call_args[1]['headers']['X-CT-API-Secret'] == 'test-secret'
                
                # Test RequestException error
                mock_get.side_effect = requests.RequestException("Connection error")
                with pytest.raises(CTLogError, match="Failed to communicate with CT service"):
                    client.get_certificate_by_fingerprint('abc123')
                
                # Test JSON parsing error
                mock_get.reset_mock()
                mock_get.side_effect = None
                mock_response = Mock()
                mock_response.json.side_effect = ValueError("Invalid JSON")
                mock_get.return_value = mock_response
                with pytest.raises(CTLogError, match="Invalid response from CT service"):
                    client.get_certificate_by_fingerprint('abc123')

    def test_revoke_certificate(self, app):
        """Test certificate revocation functionality."""
        with app.app_context():
            client = CTLogClient(api_secret='test-secret')
            
            # Test missing API secret
            client_no_secret = CTLogClient(api_secret=None)
            with pytest.raises(CTLogError, match="CT service API secret not configured"):
                client_no_secret.revoke_certificate('abc123', 'key_compromise', 'admin')
            
            with patch('requests.post') as mock_post, \
                 patch('app.utils.certtransparency_client.current_app.logger') as mock_logger:
                
                # Test successful revocation
                mock_response = Mock()
                mock_response.json.return_value = {'status': 'revoked'}
                mock_post.return_value = mock_response
                
                result = client.revoke_certificate('abc123', 'key_compromise', 'admin')
                assert result == {'status': 'revoked'}
                
                # Verify request
                call_args = mock_post.call_args
                assert 'abc123/revoke' in call_args[0][0]
                assert call_args[1]['json'] == {
                    'reason': 'key_compromise',
                    'revoked_by': 'admin'
                }
                
                # Test RequestException error
                mock_post.side_effect = requests.RequestException("Connection error")
                with pytest.raises(CTLogError, match="Failed to communicate with CT service"):
                    client.revoke_certificate('abc123', 'key_compromise', 'admin')
                
                # Test JSON parsing error
                mock_post.reset_mock()
                mock_post.side_effect = None
                mock_response = Mock()
                mock_response.json.side_effect = ValueError("Invalid JSON")
                mock_post.return_value = mock_response
                with pytest.raises(CTLogError, match="Invalid response from CT service"):
                    client.revoke_certificate('abc123', 'key_compromise', 'admin')

    def test_bulk_revoke_user_certificates(self, app):
        """Test bulk certificate revocation functionality."""
        with app.app_context():
            client = CTLogClient(api_secret='test-secret')
            
            # Test missing API secret
            client_no_secret = CTLogClient(api_secret=None)
            with pytest.raises(CTLogError, match="CT service API secret not configured"):
                client_no_secret.bulk_revoke_user_certificates('user123', 'key_compromise', 'admin')
            
            with patch('requests.post') as mock_post, \
                 patch('app.utils.certtransparency_client.current_app.logger') as mock_logger:
                
                # Test successful bulk revocation
                mock_response = Mock()
                mock_response.json.return_value = {'revoked_count': 5}
                mock_post.return_value = mock_response
                
                result = client.bulk_revoke_user_certificates('user123', 'cessation_of_operation', 'admin')
                assert result == {'revoked_count': 5}
                
                # Verify request
                call_args = mock_post.call_args
                assert 'users/user123/revoke-certificates' in call_args[0][0]
                assert call_args[1]['json'] == {
                    'reason': 'cessation_of_operation',
                    'revoked_by': 'admin'
                }
                
                # Test error scenarios  
                mock_post.reset_mock()
                mock_post.side_effect = requests.RequestException("Connection error")
                with pytest.raises(CTLogError, match="Failed to communicate with CT service"):
                    client.bulk_revoke_user_certificates('user123', 'key_compromise', 'admin')
                
                # Test JSON error
                mock_post.reset_mock()
                mock_post.side_effect = None  # Clear side_effect
                mock_response = Mock()
                mock_response.json.side_effect = ValueError("Invalid JSON")
                mock_post.return_value = mock_response
                with pytest.raises(CTLogError, match="Invalid response from CT service"):
                    client.bulk_revoke_user_certificates('user123', 'key_compromise', 'admin')


class TestConvenienceFunctions:
    """Test suite for convenience functions."""
    
    def test_log_certificate_to_ct_success(self, app):
        """Test successful certificate logging via convenience function."""
        with app.app_context():
            # Create a test certificate
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            cert = x509.CertificateBuilder().subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
            ).issuer_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
            ).public_key(
                private_key.public_key()
            ).serial_number(
                1
            ).not_valid_before(
                datetime.now(timezone.utc)
            ).not_valid_after(
                datetime.now(timezone.utc) + timedelta(days=365)
            ).sign(private_key, algorithm=hashes.SHA256())
            
            with patch('app.utils.certtransparency_client.CTLogClient') as mock_client_class, \
                 patch('app.utils.certtransparency_client.current_app.logger') as mock_logger:
                
                # Mock successful logging
                mock_client = Mock()
                mock_client.log_certificate.return_value = {'status': 'logged'}
                mock_client_class.return_value = mock_client
                
                # Test with all parameters
                requester_info = {'ip': '192.168.1.1'}
                result = log_certificate_to_ct(
                    certificate=cert,
                    certificate_type='server',
                    certificate_purpose='test-server',
                    requester_info=requester_info,
                    issuing_user_id='user123'
                )
                
                assert result == {'status': 'logged'}
                
                # Verify client was created and called
                mock_client_class.assert_called_once()
                mock_client.log_certificate.assert_called_once()
                call_kwargs = mock_client.log_certificate.call_args[1]
                assert 'BEGIN CERTIFICATE' in call_kwargs['certificate_pem']
                assert call_kwargs['certificate_type'] == 'server'
                assert call_kwargs['certificate_purpose'] == 'test-server'
                assert call_kwargs['requester_info'] == requester_info
                assert call_kwargs['issuing_user_id'] == 'user123'

    def test_log_certificate_to_ct_error_handling(self, app):
        """Test convenience function error handling."""
        with app.app_context():
            # Create a test certificate
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            cert = x509.CertificateBuilder().subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
            ).issuer_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
            ).public_key(
                private_key.public_key()
            ).serial_number(
                1
            ).not_valid_before(
                datetime.now(timezone.utc)
            ).not_valid_after(
                datetime.now(timezone.utc) + timedelta(days=365)
            ).sign(private_key, algorithm=hashes.SHA256())
            
            with patch('app.utils.certtransparency_client.CTLogClient') as mock_client_class, \
                 patch('app.utils.certtransparency_client.current_app.logger') as mock_logger:
                
                # Mock client to raise exception
                mock_client = Mock()
                mock_client.log_certificate.side_effect = CTLogError("Service error")
                mock_client_class.return_value = mock_client
                
                # Test error handling
                result = log_certificate_to_ct(certificate=cert, certificate_type='client')
                
                assert result is None
                mock_logger.error.assert_called_once()

    def test_get_ct_client(self):
        """Test get_ct_client convenience function."""
        with patch('app.utils.certtransparency_client.CTLogClient') as mock_client_class:
            mock_client = Mock()
            mock_client_class.return_value = mock_client
            
            result = get_ct_client()
            
            assert result == mock_client
            mock_client_class.assert_called_once()


class TestCTLogError:
    """Test the CTLogError exception class."""
    
    def test_ctlog_error(self):
        """Test CTLogError creation and inheritance."""
        error_msg = "Test error message"
        error = CTLogError(error_msg)
        
        assert isinstance(error, Exception)
        assert str(error) == error_msg
        
        # Test it can be raised and caught
        with pytest.raises(CTLogError, match="Test error message"):
            raise CTLogError(error_msg)