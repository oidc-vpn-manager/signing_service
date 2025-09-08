"""
Unit tests for Certificate Transparency client functionality.

Tests the CT client integration in the signing service.
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from requests.exceptions import RequestException, Timeout, ConnectionError

from app import create_app
from app.utils.certtransparency_client import (
    CTLogClient,
    CTLogError, 
    log_certificate_to_ct,
    get_ct_client
)


class TestCTLogClient:
    """Test suite for CTLogClient."""

    @pytest.fixture
    def app(self):
        """Create test Flask app."""
        app = create_app()
        app.config.update({
            'TESTING': True,
            'CERTTRANSPARENCY_SERVICE_URL': 'http://localhost:5002/api/v1',
            'CT_SERVICE_API_SECRET': 'test-secret'
        })
        return app

    @pytest.fixture
    def sample_cert_pem(self):
        """Sample certificate PEM for testing."""
        return """-----BEGIN CERTIFICATE-----
MIIByDCCAXqgAwIBAgIURPck4SWVXLwaYy4atIxbKKOqpiowBQYDK2VwMG0xCzAJ
BgNVBAYTAkdCMRAwDgYDVQQIDAdFbmdsYW5kMQ8wDQYDVQQHDAZMb25kb24xGDAW
BgNVBAoMD09wZW5WUE4gU2VydmljZTEhMB8GA1UEAwwYcm9vdC5vcGVudnBuLmV4
YW1wbGUub3JnMB4XDTI1MDgwNzIzMDAxNVoXDTM1MDgwNTIzMDAxNVowczELMAkG
A1UEBhMCR0IxEDAOBgNVBAgMB0VuZ2xhbmQxDzANBgNVBAcMBkxvbmRvbjEYMBYG
A1UECgwPT3BlblZQTiBTZXJ2aWNlMScwJQYDVQQDDB4yMDI1LTA4LTA4Lm9wZW52
cG4uZXhhbXBsZS5vcmcwKjAFBgMrZXADIQBPJTd17o9DPnCIP4DWQH/QafJPixjR
VcSYCSRe7ppcjaMmMCQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMC
AQYwBQYDK2VwA0EADuc5sAf/zveAC0UpP7bNrjAydi2tQTivqW5Kr87H4nmQCVuQ
7oiKVdTQQtNUiV/q8cOq8XoM7kdf0s/Us1JyCg==
-----END CERTIFICATE-----"""

    def test_client_initialization(self, app):
        """Test CT client initialization."""
        with app.app_context():
            client = CTLogClient()
            assert client.base_url == 'http://localhost:5002/api/v1'
            assert client.api_secret == 'test-secret'
            assert client.timeout == 30

    def test_client_missing_api_secret(self, app):
        """Test CT client when API secret is not configured."""
        app.config['CT_SERVICE_API_SECRET'] = None
        with app.app_context():
            client = CTLogClient()
            assert client.api_secret is None

    @patch('app.utils.certtransparency_client.requests.post')
    def test_log_certificate_success(self, mock_post, app, sample_cert_pem):
        """Test successful certificate logging."""
        with app.app_context():
            # Mock successful response
            mock_response = Mock()
            mock_response.status_code = 201
            mock_response.json.return_value = {
                'status': 'logged',
                'certificate': {
                    'fingerprint_sha256': 'abc123def456',
                    'subject': {'common_name': 'test.example.com'}
                }
            }
            mock_post.return_value = mock_response

            client = CTLogClient()
            result = client.log_certificate(
                sample_cert_pem,
                'client',
                certificate_purpose='Test certificate'
            )

            # Verify the request was made correctly
            mock_post.assert_called_once()
            call_args = mock_post.call_args
            assert call_args[1]['json']['certificate_pem'] == sample_cert_pem
            assert call_args[1]['json']['certificate_type'] == 'client'
            assert call_args[1]['json']['certificate_purpose'] == 'Test certificate'
            assert call_args[1]['headers']['X-CT-API-Secret'] == 'test-secret'

            assert result['status'] == 'logged'

    def test_log_certificate_no_api_secret(self, app, sample_cert_pem):
        """Test logging certificate when API secret is not configured."""
        app.config['CT_SERVICE_API_SECRET'] = None
        with app.app_context():
            client = CTLogClient()
            
            with pytest.raises(CTLogError) as exc_info:
                client.log_certificate(sample_cert_pem, 'client')
            
            assert 'CT service API secret not configured' in str(exc_info.value)

    @patch('app.utils.certtransparency_client.requests.post')
    def test_log_certificate_request_exception(self, mock_post, app, sample_cert_pem):
        """Test certificate logging with request exception."""
        with app.app_context():
            mock_post.side_effect = ConnectionError('Connection failed')
            client = CTLogClient()

            with pytest.raises(CTLogError) as exc_info:
                client.log_certificate(sample_cert_pem, 'client')
            
            assert 'Failed to communicate with CT service' in str(exc_info.value)

    @patch('app.utils.certtransparency_client.requests.post')
    def test_log_certificate_timeout_exception(self, mock_post, app, sample_cert_pem):
        """Test certificate logging with timeout exception."""
        with app.app_context():
            mock_post.side_effect = Timeout('Request timed out')
            client = CTLogClient()

            with pytest.raises(CTLogError) as exc_info:
                client.log_certificate(sample_cert_pem, 'client')
            
            assert 'Failed to communicate with CT service' in str(exc_info.value)

    @patch('app.utils.certtransparency_client.requests.post')
    def test_log_certificate_invalid_json_response(self, mock_post, app, sample_cert_pem):
        """Test certificate logging with invalid JSON response."""
        with app.app_context():
            mock_response = Mock()
            mock_response.status_code = 201
            mock_response.json.side_effect = ValueError('Invalid JSON')
            mock_post.return_value = mock_response
            client = CTLogClient()

            with pytest.raises(CTLogError) as exc_info:
                client.log_certificate(sample_cert_pem, 'client')
            
            assert 'Invalid response from CT service' in str(exc_info.value)

    @patch('app.utils.certtransparency_client.requests.post')
    def test_log_certificate_with_requester_info(self, mock_post, app, sample_cert_pem):
        """Test certificate logging with requester information."""
        with app.app_context():
            mock_response = Mock()
            mock_response.status_code = 201
            mock_response.json.return_value = {'status': 'logged', 'certificate': {}}
            mock_post.return_value = mock_response
            client = CTLogClient()

            requester_info = {
                'service': 'signing-service',
                'source_ip': '192.168.1.100'
            }

            client.log_certificate(
                sample_cert_pem,
                'server',
                requester_info=requester_info
            )

            # Verify requester info was included
            call_args = mock_post.call_args
            assert call_args[1]['json']['requester_info'] == requester_info

    def test_get_ct_client(self, app):
        """Test getting CT client instance."""
        with app.app_context():
            client = get_ct_client()
            assert isinstance(client, CTLogClient)
            assert client.base_url == 'http://localhost:5002/api/v1'


class TestLogCertificateToCT:
    """Test suite for log_certificate_to_ct function."""

    @pytest.fixture
    def app(self):
        """Create test Flask app."""
        app = create_app()
        app.config.update({
            'TESTING': True,
            'CERTTRANSPARENCY_SERVICE_URL': 'http://localhost:5002/api/v1',
            'CT_SERVICE_API_SECRET': 'test-secret'
        })
        return app

    @pytest.fixture
    def mock_cert(self):
        """Mock certificate object."""
        from cryptography import x509
        mock_cert = Mock(spec=x509.Certificate)
        mock_cert.public_bytes.return_value = b'mock-pem-bytes'
        return mock_cert

    def test_log_certificate_to_ct_success(self, mock_cert, app):
        """Test successful certificate logging via helper function."""
        with app.app_context():
            with patch('app.utils.certtransparency_client.CTLogClient') as mock_client_class:
                mock_client = Mock()
                mock_client.log_certificate.return_value = {'status': 'logged'}
                mock_client_class.return_value = mock_client

                result = log_certificate_to_ct(
                    mock_cert,
                    'client',
                    certificate_purpose='Test cert',
                    requester_info={'source': 'test'}
                )

                # Verify client was called correctly
                mock_client.log_certificate.assert_called_once()
                call_args = mock_client.log_certificate.call_args[1]
                assert call_args['certificate_type'] == 'client'
                assert call_args['certificate_purpose'] == 'Test cert'
                assert call_args['requester_info'] == {'source': 'test'}

                assert result['status'] == 'logged'

    def test_log_certificate_to_ct_exception(self, mock_cert, app):
        """Test certificate logging with exception."""
        with app.app_context():
            with patch('app.utils.certtransparency_client.CTLogClient') as mock_client_class:
                mock_client = Mock()
                mock_client.log_certificate.side_effect = CTLogError('CT service error')
                mock_client_class.return_value = mock_client

                # Should not raise exception, should return None
                result = log_certificate_to_ct(mock_cert, 'client')
                assert result is None

    def test_log_certificate_to_ct_generic_exception(self, mock_cert, app):
        """Test certificate logging with generic exception."""
        with app.app_context():
            with patch('app.utils.certtransparency_client.CTLogClient') as mock_client_class:
                mock_client = Mock()
                mock_client.log_certificate.side_effect = Exception('Generic error')
                mock_client_class.return_value = mock_client

                # Should not raise exception, should return None
                result = log_certificate_to_ct(mock_cert, 'client')
                assert result is None