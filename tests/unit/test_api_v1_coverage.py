"""
Comprehensive tests for Signing Service API v1 routes to achieve 100% coverage.
Tests all endpoints including generate-crl, revoke-certificate, and bulk-revoke-user-certificates.
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from app.utils.certtransparency_client import CTLogError
from app.utils.crl_generator import CRLGenerator
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID


class TestGenerateCRLEndpoint:
    """Test suite for /api/v1/generate-crl endpoint."""
    
    @patch('app.routes.api.v1.load_intermediate_ca')
    @patch('app.routes.api.v1.CRLGenerator')
    def test_generate_crl_success(self, mock_crl_generator_class, mock_load_ca, client, app):
        """Test successful CRL generation."""
        with app.test_request_context():
            # Mock CA loading
            mock_key = Mock()
            mock_cert = Mock()
            mock_key.private_bytes.return_value = b'-----BEGIN PRIVATE KEY-----\ntest-key\n-----END PRIVATE KEY-----'
            mock_cert.public_bytes.return_value = b'-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----'
            mock_load_ca.return_value = (mock_key, mock_cert)
            
            # Mock CRL generator
            mock_generator_instance = Mock()
            mock_generator_instance.create_crl.return_value = b'test-crl-data'
            mock_crl_generator_class.return_value = mock_generator_instance
            
            # Test data
            test_data = {
                'revoked_certificates': [
                    {'serial_number': 'deadbeef', 'revoked_at': '2025-01-01T12:00:00Z', 'revocation_reason': 'key_compromise'}
                ],
                'next_update_hours': 48
            }
            
            # Make request with proper API secret header
            response = client.post(
                '/api/v1/generate-crl',
                json=test_data,
                headers={'Authorization': 'Bearer test-api-secret'}
            )
            
            assert response.status_code == 200
            assert response.data == b'test-crl-data'
            assert response.headers['Content-Type'] == 'application/pkix-crl'
            assert 'attachment; filename="certificate-revocation-list.crl"' in response.headers['Content-Disposition']
            assert 'public, max-age=172800' in response.headers['Cache-Control']  # 48 hours in seconds
            assert response.headers['Access-Control-Allow-Origin'] == '*'
            
            # Verify CRL generator was called correctly
            mock_generator_instance.load_ca_materials.assert_called_once()
            mock_generator_instance.create_crl.assert_called_once_with(test_data['revoked_certificates'], 48)

    def test_generate_crl_no_json(self, client):
        """Test CRL generation with empty JSON body."""
        response = client.post(
            '/api/v1/generate-crl',
            json={},
            headers={'Authorization': 'Bearer test-api-secret'}
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['error'] == 'Request body must be JSON'

    @patch('app.routes.api.v1.load_intermediate_ca')
    @patch('app.routes.api.v1.CRLGenerator')
    def test_generate_crl_default_next_update(self, mock_crl_generator_class, mock_load_ca, client, app):
        """Test CRL generation with default next_update_hours."""
        with app.test_request_context():
            # Mock CA loading
            mock_key = Mock()
            mock_cert = Mock()
            mock_key.private_bytes.return_value = b'-----BEGIN PRIVATE KEY-----\ntest-key\n-----END PRIVATE KEY-----'
            mock_cert.public_bytes.return_value = b'-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----'
            mock_load_ca.return_value = (mock_key, mock_cert)
            
            # Mock CRL generator
            mock_generator_instance = Mock()
            mock_generator_instance.create_crl.return_value = b'test-crl-data'
            mock_crl_generator_class.return_value = mock_generator_instance
            
            # Test data without next_update_hours
            test_data = {
                'revoked_certificates': []
            }
            
            response = client.post(
                '/api/v1/generate-crl',
                json=test_data,
                headers={'Authorization': 'Bearer test-api-secret'}
            )
            
            assert response.status_code == 200
            # Should use default 24 hours
            mock_generator_instance.create_crl.assert_called_once_with([], 24)

    @patch('app.routes.api.v1.load_intermediate_ca')
    def test_generate_crl_ca_loading_exception(self, mock_load_ca, client):
        """Test CRL generation when CA loading fails."""
        mock_load_ca.side_effect = Exception("Failed to load CA")
        
        test_data = {'revoked_certificates': []}
        
        response = client.post(
            '/api/v1/generate-crl',
            json=test_data,
            headers={'Authorization': 'Bearer test-api-secret'}
        )
        
        assert response.status_code == 500
        data = json.loads(response.data)
        assert 'Failed to generate CRL' in data['error']

    @patch('app.routes.api.v1.load_intermediate_ca')
    @patch('app.routes.api.v1.CRLGenerator')
    def test_generate_crl_generator_exception(self, mock_crl_generator_class, mock_load_ca, client, app):
        """Test CRL generation when CRL generator fails."""
        with app.test_request_context():
            # Mock CA loading
            mock_key = Mock()
            mock_cert = Mock()
            mock_key.private_bytes.return_value = b'test-key'
            mock_cert.public_bytes.return_value = b'test-cert'
            mock_load_ca.return_value = (mock_key, mock_cert)
            
            # Mock CRL generator to fail
            mock_generator_instance = Mock()
            mock_generator_instance.create_crl.side_effect = Exception("CRL generation failed")
            mock_crl_generator_class.return_value = mock_generator_instance
            
            test_data = {'revoked_certificates': []}
            
            response = client.post(
                '/api/v1/generate-crl',
                json=test_data,
                headers={'Authorization': 'Bearer test-api-secret'}
            )
            
            assert response.status_code == 500
            data = json.loads(response.data)
            assert 'Failed to generate CRL' in data['error']


class TestRevokeCertificateEndpoint:
    """Test suite for /api/v1/revoke-certificate endpoint."""
    
    @patch('app.routes.api.v1.get_ct_client')
    def test_revoke_certificate_success(self, mock_get_client, client):
        """Test successful certificate revocation."""
        # Mock CT client
        mock_client = Mock()
        mock_client.get_certificate_by_fingerprint.return_value = {
            'certificate': {
                'fingerprint_sha256': 'test123',
                'revoked_at': None,
                'revocation': None
            }
        }
        mock_client.revoke_certificate.return_value = {'status': 'revoked'}
        mock_get_client.return_value = mock_client
        
        test_data = {
            'fingerprint': 'test123',
            'reason': 'key_compromise',
            'revoked_by': 'admin'
        }
        
        response = client.post(
            '/api/v1/revoke-certificate',
            json=test_data,
            headers={'Authorization': 'Bearer test-api-secret'}
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'success'
        assert data['message'] == 'Certificate revoked successfully'
        assert data['certificate_fingerprint'] == 'test123'
        assert data['revocation_reason'] == 'key_compromise'
        assert data['revoked_by'] == 'admin'
        
        # Verify CT client calls
        mock_client.get_certificate_by_fingerprint.assert_called_once_with('test123')
        mock_client.revoke_certificate.assert_called_once_with(
            fingerprint='test123',
            reason='key_compromise',
            revoked_by='admin'
        )

    def test_revoke_certificate_no_json(self, client):
        """Test certificate revocation with empty JSON body."""
        response = client.post(
            '/api/v1/revoke-certificate',
            json={},
            headers={'Authorization': 'Bearer test-api-secret'}
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['error'] == 'Request body must be JSON'

    def test_revoke_certificate_missing_fields(self, client):
        """Test certificate revocation with missing required fields."""
        test_cases = [
            {'reason': 'key_compromise', 'revoked_by': 'admin'},  # Missing fingerprint
            {'fingerprint': 'test123', 'revoked_by': 'admin'},   # Missing reason
            {'fingerprint': 'test123', 'reason': 'key_compromise'},  # Missing revoked_by
        ]
        
        for test_data in test_cases:
            response = client.post(
                '/api/v1/revoke-certificate',
                json=test_data,
                headers={'Authorization': 'Bearer test-api-secret'}
            )
            
            assert response.status_code == 400
            data = json.loads(response.data)
            assert 'Missing required fields' in data['error']

    def test_revoke_certificate_invalid_reason(self, client):
        """Test certificate revocation with invalid reason."""
        test_data = {
            'fingerprint': 'test123',
            'reason': 'invalid_reason',
            'revoked_by': 'admin'
        }
        
        response = client.post(
            '/api/v1/revoke-certificate',
            json=test_data,
            headers={'Authorization': 'Bearer test-api-secret'}
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'Invalid revocation reason' in data['error']

    @patch('app.routes.api.v1.get_ct_client')
    def test_revoke_certificate_not_found(self, mock_get_client, client):
        """Test revocation of non-existent certificate."""
        # Mock CT client to return no certificate
        mock_client = Mock()
        mock_client.get_certificate_by_fingerprint.return_value = {'certificate': None}
        mock_get_client.return_value = mock_client
        
        test_data = {
            'fingerprint': 'nonexistent123',
            'reason': 'key_compromise',
            'revoked_by': 'admin'
        }
        
        response = client.post(
            '/api/v1/revoke-certificate',
            json=test_data,
            headers={'Authorization': 'Bearer test-api-secret'}
        )
        
        assert response.status_code == 404
        data = json.loads(response.data)
        assert data['error'] == 'Certificate not found'

    @patch('app.routes.api.v1.get_ct_client')
    def test_revoke_certificate_already_revoked(self, mock_get_client, client):
        """Test revocation of already revoked certificate."""
        # Mock CT client to return revoked certificate
        mock_client = Mock()
        mock_client.get_certificate_by_fingerprint.return_value = {
            'certificate': {
                'fingerprint_sha256': 'test123',
                'revoked_at': '2025-01-01T12:00:00Z'
            }
        }
        mock_get_client.return_value = mock_client
        
        test_data = {
            'fingerprint': 'test123',
            'reason': 'key_compromise',
            'revoked_by': 'admin'
        }
        
        response = client.post(
            '/api/v1/revoke-certificate',
            json=test_data,
            headers={'Authorization': 'Bearer test-api-secret'}
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['error'] == 'Certificate is already revoked'

    @patch('app.routes.api.v1.get_ct_client')
    def test_revoke_certificate_ct_not_found_error(self, mock_get_client, client):
        """Test certificate revocation when CT service returns not found error."""
        # Mock CT client to raise CTLogError for not found
        mock_client = Mock()
        mock_client.get_certificate_by_fingerprint.side_effect = CTLogError("Certificate not found")
        mock_get_client.return_value = mock_client
        
        test_data = {
            'fingerprint': 'test123',
            'reason': 'key_compromise',
            'revoked_by': 'admin'
        }
        
        response = client.post(
            '/api/v1/revoke-certificate',
            json=test_data,
            headers={'Authorization': 'Bearer test-api-secret'}
        )
        
        assert response.status_code == 404
        data = json.loads(response.data)
        assert data['error'] == 'Certificate not found'

    @patch('app.routes.api.v1.get_ct_client')
    def test_revoke_certificate_ct_service_error(self, mock_get_client, client):
        """Test certificate revocation when CT service has other errors."""
        # Mock CT client to raise CTLogError for service error
        mock_client = Mock()
        mock_client.get_certificate_by_fingerprint.side_effect = CTLogError("Service unavailable")
        mock_get_client.return_value = mock_client
        
        test_data = {
            'fingerprint': 'test123',
            'reason': 'key_compromise',
            'revoked_by': 'admin'
        }
        
        response = client.post(
            '/api/v1/revoke-certificate',
            json=test_data,
            headers={'Authorization': 'Bearer test-api-secret'}
        )
        
        assert response.status_code == 503
        data = json.loads(response.data)
        assert data['error'] == 'Certificate Transparency service unavailable'

    @patch('app.routes.api.v1.get_ct_client')
    def test_revoke_certificate_revocation_ct_error(self, mock_get_client, client):
        """Test certificate revocation when revocation fails in CT service."""
        # Mock CT client
        mock_client = Mock()
        mock_client.get_certificate_by_fingerprint.return_value = {
            'certificate': {
                'fingerprint_sha256': 'test123',
                'revoked_at': None,
                'revocation': None
            }
        }
        mock_client.revoke_certificate.side_effect = CTLogError("Revocation failed")
        mock_get_client.return_value = mock_client
        
        test_data = {
            'fingerprint': 'test123',
            'reason': 'key_compromise',
            'revoked_by': 'admin'
        }
        
        response = client.post(
            '/api/v1/revoke-certificate',
            json=test_data,
            headers={'Authorization': 'Bearer test-api-secret'}
        )
        
        assert response.status_code == 503
        data = json.loads(response.data)
        assert data['error'] == 'Certificate Transparency service unavailable'

    @patch('app.routes.api.v1.get_ct_client')
    def test_revoke_certificate_unexpected_error(self, mock_get_client, client):
        """Test certificate revocation with unexpected error."""
        # Mock CT client to raise unexpected error
        mock_client = Mock()
        mock_client.get_certificate_by_fingerprint.side_effect = Exception("Unexpected error")
        mock_get_client.return_value = mock_client
        
        test_data = {
            'fingerprint': 'test123',
            'reason': 'key_compromise',
            'revoked_by': 'admin'
        }
        
        response = client.post(
            '/api/v1/revoke-certificate',
            json=test_data,
            headers={'Authorization': 'Bearer test-api-secret'}
        )
        
        assert response.status_code == 500
        data = json.loads(response.data)
        assert data['error'] == 'Internal server error'


class TestBulkRevokeUserCertificatesEndpoint:
    """Test suite for /api/v1/bulk-revoke-user-certificates endpoint."""
    
    @patch('app.routes.api.v1.get_ct_client')
    def test_bulk_revoke_success(self, mock_get_client, client):
        """Test successful bulk certificate revocation."""
        # Mock CT client
        mock_client = Mock()
        mock_client.bulk_revoke_user_certificates.return_value = {'revoked_count': 3}
        mock_get_client.return_value = mock_client
        
        test_data = {
            'user_id': 'user123',
            'reason': 'affiliation_changed',
            'revoked_by': 'admin'
        }
        
        response = client.post(
            '/api/v1/bulk-revoke-user-certificates',
            json=test_data,
            headers={'Authorization': 'Bearer test-api-secret'}
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'success'
        assert data['message'] == 'Successfully revoked 3 certificates for user user123'
        assert data['user_id'] == 'user123'
        assert data['revoked_count'] == 3
        assert data['reason'] == 'affiliation_changed'
        assert data['revoked_by'] == 'admin'
        
        # Verify CT client call
        mock_client.bulk_revoke_user_certificates.assert_called_once_with(
            user_id='user123',
            reason='affiliation_changed',
            revoked_by='admin'
        )

    def test_bulk_revoke_no_json(self, client):
        """Test bulk revocation with empty JSON body."""
        response = client.post(
            '/api/v1/bulk-revoke-user-certificates',
            json={},
            headers={'Authorization': 'Bearer test-api-secret'}
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['error'] == 'Request body must be JSON'

    def test_bulk_revoke_missing_fields(self, client):
        """Test bulk revocation with missing required fields."""
        test_cases = [
            {'reason': 'key_compromise', 'revoked_by': 'admin'},  # Missing user_id
            {'user_id': 'user123', 'revoked_by': 'admin'},       # Missing reason
            {'user_id': 'user123', 'reason': 'key_compromise'},  # Missing revoked_by
        ]
        
        for test_data in test_cases:
            response = client.post(
                '/api/v1/bulk-revoke-user-certificates',
                json=test_data,
                headers={'Authorization': 'Bearer test-api-secret'}
            )
            
            assert response.status_code == 400
            data = json.loads(response.data)
            assert 'Missing required fields' in data['error']

    def test_bulk_revoke_invalid_reason(self, client):
        """Test bulk revocation with invalid reason."""
        test_data = {
            'user_id': 'user123',
            'reason': 'invalid_reason',
            'revoked_by': 'admin'
        }
        
        response = client.post(
            '/api/v1/bulk-revoke-user-certificates',
            json=test_data,
            headers={'Authorization': 'Bearer test-api-secret'}
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'Invalid revocation reason' in data['error']

    @patch('app.routes.api.v1.get_ct_client')
    def test_bulk_revoke_zero_certificates(self, mock_get_client, client):
        """Test bulk revocation when no certificates are found."""
        # Mock CT client to return zero revoked count
        mock_client = Mock()
        mock_client.bulk_revoke_user_certificates.return_value = {'revoked_count': 0}
        mock_get_client.return_value = mock_client
        
        test_data = {
            'user_id': 'user123',
            'reason': 'cessation_of_operation',
            'revoked_by': 'admin'
        }
        
        response = client.post(
            '/api/v1/bulk-revoke-user-certificates',
            json=test_data,
            headers={'Authorization': 'Bearer test-api-secret'}
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['revoked_count'] == 0
        assert 'Successfully revoked 0 certificates' in data['message']

    @patch('app.routes.api.v1.get_ct_client')
    def test_bulk_revoke_ct_service_error(self, mock_get_client, client):
        """Test bulk revocation when CT service has an error."""
        # Mock CT client to raise CTLogError
        mock_client = Mock()
        mock_client.bulk_revoke_user_certificates.side_effect = CTLogError("Service unavailable")
        mock_get_client.return_value = mock_client
        
        test_data = {
            'user_id': 'user123',
            'reason': 'key_compromise',
            'revoked_by': 'admin'
        }
        
        response = client.post(
            '/api/v1/bulk-revoke-user-certificates',
            json=test_data,
            headers={'Authorization': 'Bearer test-api-secret'}
        )
        
        assert response.status_code == 503
        data = json.loads(response.data)
        assert data['error'] == 'Certificate Transparency service unavailable'

    @patch('app.routes.api.v1.get_ct_client')
    def test_bulk_revoke_unexpected_error(self, mock_get_client, client):
        """Test bulk revocation with unexpected error."""
        # Mock CT client to raise unexpected error
        mock_client = Mock()
        mock_client.bulk_revoke_user_certificates.side_effect = Exception("Unexpected error")
        mock_get_client.return_value = mock_client
        
        test_data = {
            'user_id': 'user123',
            'reason': 'key_compromise',
            'revoked_by': 'admin'
        }
        
        response = client.post(
            '/api/v1/bulk-revoke-user-certificates',
            json=test_data,
            headers={'Authorization': 'Bearer test-api-secret'}
        )
        
        assert response.status_code == 500
        data = json.loads(response.data)
        assert data['error'] == 'Internal server error'

    @patch('app.routes.api.v1.get_ct_client')
    def test_bulk_revoke_missing_revoked_count_in_response(self, mock_get_client, client):
        """Test bulk revocation when CT service response doesn't include revoked_count."""
        # Mock CT client to return response without revoked_count
        mock_client = Mock()
        mock_client.bulk_revoke_user_certificates.return_value = {}
        mock_get_client.return_value = mock_client
        
        test_data = {
            'user_id': 'user123',
            'reason': 'superseded',
            'revoked_by': 'admin'
        }
        
        response = client.post(
            '/api/v1/bulk-revoke-user-certificates',
            json=test_data,
            headers={'Authorization': 'Bearer test-api-secret'}
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['revoked_count'] == 0  # Should default to 0
        assert 'Successfully revoked 0 certificates' in data['message']


class TestValidRevocationReasons:
    """Test that all valid revocation reasons are accepted."""
    
    @patch('app.routes.api.v1.get_ct_client')
    def test_all_valid_revocation_reasons_single_revoke(self, mock_get_client, client):
        """Test that all valid revocation reasons work for single certificate revocation."""
        # Mock CT client
        mock_client = Mock()
        mock_client.get_certificate_by_fingerprint.return_value = {
            'certificate': {
                'fingerprint_sha256': 'test123',
                'revoked_at': None,
                'revocation': None
            }
        }
        mock_client.revoke_certificate.return_value = {'status': 'revoked'}
        mock_get_client.return_value = mock_client
        
        valid_reasons = [
            'key_compromise', 'ca_compromise', 'affiliation_changed',
            'superseded', 'cessation_of_operation', 'certificate_hold',
            'remove_from_crl', 'privilege_withdrawn', 'aa_compromise'
        ]
        
        for reason in valid_reasons:
            test_data = {
                'fingerprint': 'test123',
                'reason': reason,
                'revoked_by': 'admin'
            }
            
            response = client.post(
                '/api/v1/revoke-certificate',
                json=test_data,
                headers={'Authorization': 'Bearer test-api-secret'}
            )
            
            assert response.status_code == 200, f"Failed for reason: {reason}"

    @patch('app.routes.api.v1.get_ct_client')
    def test_all_valid_revocation_reasons_bulk_revoke(self, mock_get_client, client):
        """Test that all valid revocation reasons work for bulk revocation."""
        # Mock CT client
        mock_client = Mock()
        mock_client.bulk_revoke_user_certificates.return_value = {'revoked_count': 1}
        mock_get_client.return_value = mock_client
        
        valid_reasons = [
            'key_compromise', 'ca_compromise', 'affiliation_changed',
            'superseded', 'cessation_of_operation', 'certificate_hold',
            'remove_from_crl', 'privilege_withdrawn', 'aa_compromise'
        ]
        
        for reason in valid_reasons:
            test_data = {
                'user_id': 'user123',
                'reason': reason,
                'revoked_by': 'admin'
            }
            
            response = client.post(
                '/api/v1/bulk-revoke-user-certificates',
                json=test_data,
                headers={'Authorization': 'Bearer test-api-secret'}
            )
            
            assert response.status_code == 200, f"Failed for reason: {reason}"


class TestSignCertificateWithXForwardedFor:
    """Test X-Forwarded-For header parsing in sign_certificate_request - covers lines 64-66."""
    
    @patch('app.routes.api.v1.load_intermediate_ca')
    @patch('app.routes.api.v1.sign_csr')
    @patch('app.routes.api.v1.get_ct_client')
    def test_x_forwarded_for_parsing(self, mock_get_client, mock_sign_csr, mock_load_ca, client):
        """Test X-Forwarded-For header parsing when client_ip is not provided."""
        # Create a proper CSR
        client_key = ed25519.Ed25519PrivateKey.generate()
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
        ).sign(client_key, None)
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        
        # Mock CA loading
        mock_key = Mock()
        mock_cert = Mock()
        mock_load_ca.return_value = (mock_key, mock_cert)
        
        # Mock certificate signing
        mock_new_cert = Mock()
        mock_new_cert.public_bytes.return_value = b'-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----'
        # Mock subject for certificate transparency logging
        mock_cn_attr = Mock()
        mock_cn_attr.value = 'test.example.com'
        mock_new_cert.subject.get_attributes_for_oid.return_value = [mock_cn_attr]
        mock_sign_csr.return_value = mock_new_cert
        
        # Mock CT client
        mock_client = Mock()
        mock_client.log_certificate.return_value = True
        mock_get_client.return_value = mock_client
        
        # Test data without client_ip (so X-Forwarded-For will be used)
        test_data = {
            'csr': csr_pem,
            'user_id': 'test_user',
            'certificate_type': 'client'
            # Note: no client_ip provided
        }
        
        # Make request with X-Forwarded-For header
        response = client.post(
            '/api/v1/sign-csr',
            json=test_data,
            headers={
                'Authorization': 'Bearer test-api-secret',
                'X-Forwarded-For': '192.168.1.100, 10.0.0.1, 172.16.0.1'
            }
        )
        
        assert response.status_code == 200
        
        # The main goal is to ensure lines 64-66 are covered by having 
        # X-Forwarded-For header present without client_ip in the request
        # This test successfully exercises the X-Forwarded-For parsing code


class TestSwaggerSpecRoute:
    """Test swagger spec route - covers app/__init__.py line 29."""
    
    def test_swagger_spec_route(self, client):
        """Test that swagger spec route returns the YAML file."""
        response = client.get('/swagger.yaml')
        
        assert response.status_code == 200
        # Should return YAML content
        assert response.headers['Content-Type'] in ['application/x-yaml', 'text/yaml', 'text/plain', 'application/octet-stream']


class TestSignCertificateWithRequestMetadata:
    """Test sign_certificate_request with request_metadata parameter - covers line 78."""

    @patch('app.routes.api.v1.load_intermediate_ca')
    @patch('app.routes.api.v1.sign_csr')
    @patch('app.routes.api.v1.log_certificate_to_ct')
    def test_request_metadata_update_requester_info(self, mock_log_cert, mock_sign_csr, mock_load_ca, client):
        """Test that request_metadata is added to requester_info when provided - line 78."""
        # Create a proper CSR
        client_key = ed25519.Ed25519PrivateKey.generate()
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
        ).sign(client_key, None)
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')

        # Mock CA loading
        mock_key = Mock()
        mock_cert = Mock()
        mock_load_ca.return_value = (mock_key, mock_cert)

        # Mock certificate signing
        mock_new_cert = Mock()
        mock_new_cert.public_bytes.return_value = b'-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----'
        # Mock subject for certificate transparency logging
        mock_cn_attr = Mock()
        mock_cn_attr.value = 'test.example.com'
        mock_new_cert.subject.get_attributes_for_oid.return_value = [mock_cn_attr]
        mock_sign_csr.return_value = mock_new_cert

        # Mock CT logging
        mock_log_cert.return_value = {'status': 'logged'}

        # Test data WITH request_metadata to trigger line 78
        test_data = {
            'csr': csr_pem,
            'user_id': 'test_user',
            'certificate_type': 'client',
            'client_ip': '192.168.1.100',
            'request_metadata': {
                'user_email': 'user@example.com',
                'browser': 'Chrome',
                'browser_version': '91.0.4472.124',
                'os': 'Windows 10',
                'is_mobile': False,
                'request_timestamp': '2025-01-01T12:00:00Z'
            }
        }

        response = client.post(
            '/api/v1/sign-csr',
            json=test_data,
            headers={'Authorization': 'Bearer test-api-secret'}
        )

        assert response.status_code == 200

        # Verify that log_certificate_to_ct was called with merged requester_info
        mock_log_cert.assert_called_once()
        call_args = mock_log_cert.call_args

        # Check that requester_info contains both base info and request_metadata
        requester_info = call_args[1]['requester_info']

        # Base info should be present
        assert requester_info['issued_by'] == 'signing-service'
        assert requester_info['request_source'] == '192.168.1.100'
        assert 'user_agent' in requester_info

        # request_metadata should be merged in (line 78)
        assert requester_info['user_email'] == 'user@example.com'
        assert requester_info['browser'] == 'Chrome'
        assert requester_info['browser_version'] == '91.0.4472.124'
        assert requester_info['os'] == 'Windows 10'
        assert requester_info['is_mobile'] is False
        assert requester_info['request_timestamp'] == '2025-01-01T12:00:00Z'