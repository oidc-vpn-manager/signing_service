"""
Test for /api/v1/sign-csr endpoint to achieve 100% coverage of missing line 54.
"""

import pytest
from unittest.mock import Mock, patch
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


class TestSignCSREndpoint:
    """Test suite for /api/v1/sign-csr endpoint to cover missing line 54."""
    
    @patch('app.routes.api.v1.log_certificate_to_ct')
    @patch('app.routes.api.v1.load_intermediate_ca')
    @patch('app.routes.api.v1.sign_csr')
    def test_sign_csr_server_certificate(self, mock_sign, mock_load_ca, mock_log_cert, client, app):
        """Test server certificate signing to cover line 54."""
        # Create a proper CSR like the integration test
        client_key = ed25519.Ed25519PrivateKey.generate()
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "server.example.com")])
        ).sign(client_key, None)

        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')

        # Mock CA and signing
        mock_cert = Mock()
        mock_subject_attr = Mock()
        mock_subject_attr.value = 'server.example.com'
        mock_cert.subject.get_attributes_for_oid.return_value = [mock_subject_attr]
        mock_cert.public_bytes.return_value = b'mock-cert-data'
        mock_cert.subject.rfc4514_string.return_value = 'CN=server.example.com'
        mock_sign.return_value = mock_cert
        mock_load_ca.return_value = (Mock(), Mock())

        # Mock CT logging
        mock_log_cert.return_value = {'status': 'logged'}
        
        response = client.post(
            '/api/v1/sign-csr',
            json={
                'csr': csr_pem,
                'certificate_type': 'server',
                'user_id': 'server-admin'
            },
            headers={'Authorization': 'Bearer test-api-secret'}
        )
        
        assert response.status_code == 200
        assert 'certificate' in response.json
        
        # Verify CT logging was called with server certificate purpose
        mock_log_cert.assert_called_once()
        call_kwargs = mock_log_cert.call_args[1]
        assert call_kwargs['certificate_type'] == 'server'
        assert 'Server certificate for server.example.com' in call_kwargs['certificate_purpose']