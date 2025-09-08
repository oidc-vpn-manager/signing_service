"""
Tests for Certificate Transparency Client module (ct_client.py).

This module tests the CTClient class which handles CRL number management
via communication with the Certificate Transparency service.
"""

import pytest
import requests
from unittest.mock import Mock, patch
from flask import Flask

from app.utils.ct_client import CTClient, CTClientError, get_ct_client


class TestCTClient:
    """Test suite for CTClient class."""
    
    def test_init_configuration(self):
        """Test client initialization and configuration."""
        # Test basic initialization
        client = CTClient('http://ct-service:8080', 'test-secret')
        assert client.ct_service_url == 'http://ct-service:8080'
        assert client.api_secret == 'test-secret'
        assert client.session.headers['Authorization'] == 'Bearer test-secret'
        assert client.session.headers['Content-Type'] == 'application/json'
        assert client.session.headers['User-Agent'] == 'OpenVPN-Signing-Service/1.0'
        
        # Test URL with trailing slash gets stripped
        client = CTClient('http://ct-service:8080/', 'test-secret')
        assert client.ct_service_url == 'http://ct-service:8080'
    
    @patch('app.utils.ct_client.requests.Session')
    def test_session_setup(self, mock_session_class):
        """Test session setup with proper headers."""
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        client = CTClient('http://ct-service:8080', 'my-secret')
        
        # Verify session was created and headers were set
        mock_session_class.assert_called_once()
        mock_session.headers.update.assert_called_once_with({
            'Authorization': 'Bearer my-secret',
            'Content-Type': 'application/json',
            'User-Agent': 'OpenVPN-Signing-Service/1.0'
        })
    
    def test_get_next_crl_number_success(self):
        """Test successful CRL number retrieval."""
        client = CTClient('http://ct-service:8080', 'test-secret')
        
        # Mock successful response
        with patch.object(client.session, 'post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {'crl_number': 42}
            mock_post.return_value = mock_response
            
            result = client.get_next_crl_number('test-issuer')
            
            # Verify the result
            assert result == 42
            
            # Verify the request
            mock_post.assert_called_once_with(
                'http://ct-service:8080/api/v1/crl/next-number',
                json={'issuer_identifier': 'test-issuer'},
                timeout=30
            )
    
    def test_get_next_crl_number_http_error(self):
        """Test CRL number retrieval with HTTP error."""
        client = CTClient('http://ct-service:8080', 'test-secret')
        
        with patch.object(client.session, 'post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 404
            mock_response.text = 'Not Found'
            mock_post.return_value = mock_response
            
            with pytest.raises(CTClientError, match="CT service returned 404: Not Found"):
                client.get_next_crl_number('test-issuer')
    
    def test_get_next_crl_number_request_exception(self):
        """Test CRL number retrieval with request exception."""
        client = CTClient('http://ct-service:8080', 'test-secret')
        
        with patch.object(client.session, 'post') as mock_post:
            mock_post.side_effect = requests.exceptions.ConnectionError("Connection failed")
            
            with pytest.raises(CTClientError, match="Failed to communicate with CT service: Connection failed"):
                client.get_next_crl_number('test-issuer')
    
    def test_get_current_crl_number_success(self):
        """Test successful current CRL number retrieval."""
        client = CTClient('http://ct-service:8080', 'test-secret')
        
        with patch.object(client.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {'current_crl_number': 17}
            mock_get.return_value = mock_response
            
            result = client.get_current_crl_number('test-issuer')
            
            # Verify the result
            assert result == 17
            
            # Verify the request
            mock_get.assert_called_once_with(
                'http://ct-service:8080/api/v1/crl/current-number/test-issuer',
                timeout=30
            )
    
    def test_get_current_crl_number_http_error(self):
        """Test current CRL number retrieval with HTTP error."""
        client = CTClient('http://ct-service:8080', 'test-secret')
        
        with patch.object(client.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 500
            mock_response.text = 'Internal Server Error'
            mock_get.return_value = mock_response
            
            with pytest.raises(CTClientError, match="CT service returned 500: Internal Server Error"):
                client.get_current_crl_number('test-issuer')
    
    def test_get_current_crl_number_request_exception(self):
        """Test current CRL number retrieval with request exception."""
        client = CTClient('http://ct-service:8080', 'test-secret')
        
        with patch.object(client.session, 'get') as mock_get:
            mock_get.side_effect = requests.exceptions.Timeout("Request timeout")
            
            with pytest.raises(CTClientError, match="Failed to communicate with CT service: Request timeout"):
                client.get_current_crl_number('test-issuer')


class TestGetCTClient:
    """Test suite for get_ct_client factory function."""
    
    def test_get_ct_client_success(self):
        """Test successful CT client creation."""
        app = Flask(__name__)
        app.config['CERTTRANSPARENCY_SERVICE_URL'] = 'http://ct-service:8080'
        app.config['CT_SERVICE_API_SECRET'] = 'test-secret'
        
        with app.app_context():
            client = get_ct_client()
            
            assert isinstance(client, CTClient)
            assert client.ct_service_url == 'http://ct-service:8080'
            assert client.api_secret == 'test-secret'
    
    def test_get_ct_client_missing_url(self):
        """Test CT client creation with missing URL."""
        app = Flask(__name__)
        app.config['CT_SERVICE_API_SECRET'] = 'test-secret'
        
        with app.app_context():
            with pytest.raises(CTClientError, match="CERTTRANSPARENCY_SERVICE_URL is not configured"):
                get_ct_client()
    
    def test_get_ct_client_missing_secret(self):
        """Test CT client creation with missing API secret."""
        app = Flask(__name__)
        app.config['CERTTRANSPARENCY_SERVICE_URL'] = 'http://ct-service:8080'
        
        with app.app_context():
            with pytest.raises(CTClientError, match="CT_SERVICE_API_SECRET is not configured"):
                get_ct_client()
    
    def test_get_ct_client_missing_both(self):
        """Test CT client creation with both URL and secret missing."""
        app = Flask(__name__)
        
        with app.app_context():
            with pytest.raises(CTClientError, match="CERTTRANSPARENCY_SERVICE_URL is not configured"):
                get_ct_client()


class TestCTClientError:
    """Test the CTClientError exception class."""
    
    def test_ctclient_error(self):
        """Test CTClientError creation and inheritance."""
        error_msg = "Test CT client error"
        error = CTClientError(error_msg)
        
        assert isinstance(error, Exception)
        assert str(error) == error_msg
        
        # Test it can be raised and caught
        with pytest.raises(CTClientError, match="Test CT client error"):
            raise CTClientError(error_msg)