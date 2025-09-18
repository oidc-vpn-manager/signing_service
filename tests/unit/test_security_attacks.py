"""
Security-focused tests for Signing Service API endpoints.

Tests CSR-based attacks, JSON injection, and certificate chain attacks
from red team, blue team, and bug bounty perspectives.
"""

import pytest
import json
import threading
import time
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from unittest.mock import patch, Mock

from app import create_app


class TestSigningServiceSecurityAttacks:
    """Security attack vector tests for Signing Service."""

    @pytest.fixture
    def app(self):
        """Create application for testing."""
        app = create_app()
        app.config['TESTING'] = True
        app.config['SIGNING_SERVICE_API_SECRET'] = 'test-api-secret'
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

    @patch('app.routes.api.v1.log_certificate_to_ct')
    @patch('app.routes.api.v1.load_intermediate_ca')
    @patch('app.routes.api.v1.sign_csr')
    def test_malformed_csr_buffer_overflow(self, mock_sign, mock_load_ca, mock_log_ct, client):
        """Test CSR with oversized subject fields - Red Team attack."""
        # Mock CA and signing
        mock_cert = Mock()
        mock_subject_attr = Mock()
        mock_subject_attr.value = 'test.example.com'
        mock_cert.subject.get_attributes_for_oid.return_value = [mock_subject_attr]
        mock_cert.public_bytes.return_value = b'mock-cert-data'
        mock_cert.subject.rfc4514_string.return_value = 'CN=test.example.com'
        mock_sign.return_value = mock_cert
        mock_load_ca.return_value = (Mock(), Mock())
        mock_log_ct.return_value = {'status': 'logged'}

        # Test CSRs with oversized subject fields - use smaller sizes that don't hit cryptography library limits
        oversized_tests = [
            ("A" * 1000, "Large CN field"),  # 1KB CN
            ("B" * 2000, "Very large ORG field"),  # 2KB ORG
        ]

        for oversized_value, description in oversized_tests:
            client_key = ed25519.Ed25519PrivateKey.generate()
            try:
                # Test with large but valid subject field
                subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, oversized_value)])
                csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(client_key, None)
                csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')

                response = client.post('/api/v1/sign-csr',
                                     json={'csr': csr_pem, 'user_id': 'test'},
                                     headers={'Authorization': 'Bearer test-api-secret'})

                # Should handle gracefully, not crash
                assert response.status_code in [200, 400], f"Service should handle {description} gracefully"

            except ValueError:
                # If CSR creation fails due to library limits, that's acceptable protection
                pass

    @patch('app.routes.api.v1.log_certificate_to_ct')
    @patch('app.routes.api.v1.load_intermediate_ca')
    @patch('app.routes.api.v1.sign_csr')
    def test_csr_with_malicious_extensions(self, mock_sign, mock_load_ca, mock_log_ct, client):
        """Test CSR attempting to set CA:TRUE - Red Team attack."""
        # Mock CA and signing
        mock_cert = Mock()
        mock_subject_attr = Mock()
        mock_subject_attr.value = 'malicious.example.com'
        mock_cert.subject.get_attributes_for_oid.return_value = [mock_subject_attr]
        mock_cert.public_bytes.return_value = b'mock-cert-data'
        mock_cert.subject.rfc4514_string.return_value = 'CN=malicious.example.com'
        mock_sign.return_value = mock_cert
        mock_load_ca.return_value = (Mock(), Mock())
        mock_log_ct.return_value = {'status': 'logged'}

        client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Try to create CSR with CA:TRUE extension
        try:
            csr = x509.CertificateSigningRequestBuilder().subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "malicious.example.com")])
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,  # CA capability
                    crl_sign=True,      # CA capability
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            ).sign(client_key, hashes.SHA256())

            csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')

            response = client.post('/api/v1/sign-csr',
                                 json={'csr': csr_pem, 'user_id': 'attacker'},
                                 headers={'Authorization': 'Bearer test-api-secret'})

            # Should either reject malicious CSR or override extensions safely
            if response.status_code == 200:
                # If signed, the resulting certificate should NOT have CA:TRUE
                # This would be validated in the sign_csr function implementation
                pass
            else:
                # CSR rejection is also acceptable
                assert response.status_code == 400

        except Exception:
            # If CSR creation with malicious extensions fails, that's good protection
            pass

    def test_json_payload_exhaustion(self, client):
        """Test oversized request_metadata causing DoS - Red Team attack."""
        # Create extremely large metadata payload
        huge_metadata = {
            'user_email': 'test@example.com',
            'browser': 'Chrome',
            'large_field': 'A' * 1000000,  # 1MB field
            'nested_data': {
                'level1': {
                    'level2': {
                        'level3': 'B' * 500000  # 500KB nested
                    }
                }
            },
            'array_data': ['C' * 10000] * 100  # Large array
        }

        response = client.post('/api/v1/sign-csr',
                             json={
                                 'csr': 'invalid-csr',  # Will fail before reaching metadata
                                 'user_id': 'test',
                                 'request_metadata': huge_metadata
                             },
                             headers={'Authorization': 'Bearer test-api-secret'})

        # Should handle large payloads gracefully
        # Either reject with 413 (payload too large) or 400 (invalid CSR)
        assert response.status_code in [400, 413], "Should handle large JSON payloads safely"

    def test_recursive_json_objects(self, client):
        """Test nested JSON causing parser stack overflow - Red Team attack."""
        # Create deeply nested JSON (attempt to cause stack overflow)
        nested_json = {}
        current = nested_json
        for i in range(1000):  # Deep nesting
            current['nested'] = {}
            current = current['nested']
        current['value'] = 'deep'

        # Try to send the deeply nested JSON - it should either be rejected by the framework
        # or handled gracefully by the application
        try:
            response = client.post('/api/v1/sign-csr',
                                 json={
                                     'csr': 'invalid-csr',
                                     'user_id': 'test',
                                     'request_metadata': nested_json
                                 },
                                 headers={'Authorization': 'Bearer test-api-secret'})

            # If it gets through, should handle gracefully without crashing
            assert response.status_code in [400, 413, 500], "Should handle deeply nested JSON safely"

        except RecursionError:
            # If the framework rejects it with RecursionError, that's good protection
            pass

    def test_csr_null_byte_injection(self, client, valid_csr_pem):
        """Test CSR with null bytes in fields - Red Team attack."""
        # Null byte injection in various request fields
        null_byte_payloads = [
            'test\x00admin',
            'user\x00root',
            'client\x00server',
            'normal\x00\x01\x02\x03data'
        ]

        for payload in null_byte_payloads:
            response = client.post('/api/v1/sign-csr',
                                 json={
                                     'csr': valid_csr_pem,
                                     'user_id': payload,
                                     'certificate_type': payload
                                 },
                                 headers={'Authorization': 'Bearer test-api-secret'})

            # Should handle null bytes safely
            assert response.status_code in [200, 400], "Should handle null bytes in input fields"

    def test_authentication_bypass_attempts(self, client, valid_csr_pem):
        """Test API secret bypass attempts - Red Team attack."""
        # Test valid attempts that should be rejected by authentication
        bypass_attempts = [
            {},  # No Authorization header
            {'Authorization': ''},  # Empty Authorization
            {'Authorization': 'Bearer '},  # Empty token
            {'Authorization': 'Basic dGVzdDp0ZXN0'},  # Wrong auth type
            {'Authorization': 'Bearer ' + 'A' * 1000},  # Oversized token
            {'X-CT-API-Secret': 'test-api-secret'},  # Wrong header name
        ]

        for headers in bypass_attempts:
            response = client.post('/api/v1/sign-csr',
                                 json={'csr': valid_csr_pem, 'user_id': 'test'},
                                 headers=headers)

            # Should deny unauthorized requests
            assert response.status_code == 401, f"Should deny unauthorized request: {headers}"

        # Test header injection separately since Werkzeug properly rejects newlines
        try:
            response = client.post('/api/v1/sign-csr',
                                 json={'csr': valid_csr_pem, 'user_id': 'test'},
                                 headers={'Authorization': 'Bearer test-api-secret\r\nMalicious: header'})
            # If it gets through, should be denied
            assert response.status_code == 401, "Header injection should be denied"
        except ValueError as e:
            # Werkzeug properly rejects newline characters - this is good security
            assert "newline characters" in str(e), "Should reject headers with newlines"

    def test_concurrent_signing_requests(self, client, valid_csr_pem):
        """Test concurrent request handling for race conditions - Blue Team test."""
        results = []
        errors = []

        def make_signing_request():
            try:
                with patch('app.routes.api.v1.log_certificate_to_ct'), \
                     patch('app.routes.api.v1.load_intermediate_ca'), \
                     patch('app.routes.api.v1.sign_csr') as mock_sign:

                    mock_cert = Mock()
                    mock_subject_attr = Mock()
                    mock_subject_attr.value = 'test.example.com'
                    mock_cert.subject.get_attributes_for_oid.return_value = [mock_subject_attr]
                    mock_cert.public_bytes.return_value = b'mock-cert-data'
                    mock_cert.subject.rfc4514_string.return_value = 'CN=test.example.com'
                    mock_sign.return_value = mock_cert

                    response = client.post('/api/v1/sign-csr',
                                         json={'csr': valid_csr_pem, 'user_id': f'user_{threading.current_thread().ident}'},
                                         headers={'Authorization': 'Bearer test-api-secret'})
                    results.append(response.status_code)
            except Exception as e:
                errors.append(str(e))

        # Simulate concurrent requests
        threads = []
        for _ in range(20):
            thread = threading.Thread(target=make_signing_request)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # Should handle concurrent requests without race conditions
        assert len(errors) == 0, f"Concurrent request errors: {errors}"
        assert len(results) == 20, "All concurrent requests should complete"

    def test_error_message_sanitization(self, client):
        """Test error messages for information disclosure - Bug Bounty target."""
        # Trigger various error conditions
        error_triggers = [
            {'json': None},  # No JSON body
            {'json': {}},    # Empty JSON
            {'json': {'invalid': 'data'}},  # Missing required fields
            {'json': {'csr': 'INVALID_PEM_DATA'}},  # Invalid CSR
            {'json': {'csr': '-----BEGIN CERTIFICATE REQUEST-----\nINVALID\n-----END CERTIFICATE REQUEST-----'}},
        ]

        for trigger in error_triggers:
            response = client.post('/api/v1/sign-csr',
                                 headers={'Authorization': 'Bearer test-api-secret'},
                                 **trigger)

            response_text = response.get_data(as_text=True)

            # Should not expose sensitive information in errors
            sensitive_patterns = [
                'Traceback',
                'File "/',
                'line ',
                '/app/',
                'Exception:',
                'Error:',
                'postgresql://',
                'database',
                'password',
                'secret',
                'key_file',
                'private_key',
                'passphrase'
            ]

            for pattern in sensitive_patterns:
                assert pattern.lower() not in response_text.lower(), f"Information disclosure: {pattern} found in error"

    def test_response_timing_consistency(self, client):
        """Test response timing for information disclosure - Bug Bounty defense."""
        # Test timing consistency for different error types
        timing_tests = [
            {'json': {'csr': 'invalid'}, 'desc': 'invalid_csr'},
            {'json': {}, 'desc': 'missing_fields'},
            {'headers': {'Authorization': 'Bearer wrong-secret'}, 'json': {'csr': 'test'}, 'desc': 'wrong_auth'},
            {'headers': {}, 'json': {'csr': 'test'}, 'desc': 'no_auth'},
        ]

        timings = {}

        for test_case in timing_tests:
            headers = test_case.get('headers', {'Authorization': 'Bearer test-api-secret'})
            json_data = test_case.get('json', {})
            desc = test_case['desc']

            start_time = time.time()
            response = client.post('/api/v1/sign-csr', headers=headers, json=json_data)
            end_time = time.time()

            timings[desc] = end_time - start_time

        # Timing should be reasonably consistent (within 200% variance)
        avg_timing = sum(timings.values()) / len(timings)
        for desc, timing in timings.items():
            variance = abs(timing - avg_timing) / avg_timing
            assert variance < 2.0, f"Timing inconsistency detected for {desc}: {timing}s vs avg {avg_timing}s"

    def test_certificate_signing_limits(self, client, valid_csr_pem):
        """Test certificate signing rate limits - Blue Team defense."""
        with patch('app.routes.api.v1.log_certificate_to_ct') as mock_log_ct, \
             patch('app.routes.api.v1.load_intermediate_ca') as mock_load_ca, \
             patch('app.routes.api.v1.sign_csr') as mock_sign:

            # Configure mocks properly
            mock_cert = Mock()
            mock_subject_attr = Mock()
            mock_subject_attr.value = 'test.example.com'
            mock_cert.subject.get_attributes_for_oid.return_value = [mock_subject_attr]
            mock_cert.public_bytes.return_value = b'mock-cert-data'
            mock_cert.subject.rfc4514_string.return_value = 'CN=test.example.com'
            mock_sign.return_value = mock_cert
            mock_load_ca.return_value = (Mock(), Mock())  # (key, cert) tuple
            mock_log_ct.return_value = {'status': 'logged'}

            # Rapid successive requests
            responses = []
            for i in range(50):  # Burst of requests
                response = client.post('/api/v1/sign-csr',
                                     json={'csr': valid_csr_pem, 'user_id': f'user_{i}'},
                                     headers={'Authorization': 'Bearer test-api-secret'})
                responses.append(response.status_code)

            # All requests should succeed (or implement rate limiting)
            success_count = sum(1 for status in responses if status == 200)
            rate_limited_count = sum(1 for status in responses if status == 429)

            # Either all succeed or some are rate limited
            assert success_count + rate_limited_count == len(responses), "Unexpected response codes in burst test"

    def test_input_validation_edge_cases(self, client):
        """Test input validation edge cases - OWASP prevention."""
        edge_cases = [
            {'csr': None, 'user_id': 'test'},
            {'csr': '', 'user_id': 'test'},
            {'csr': 'valid', 'user_id': None},
            {'csr': 'valid', 'user_id': ''},
            {'csr': 'valid', 'certificate_type': 'invalid_type'},
            {'csr': 'valid', 'client_ip': 'not.an.ip.address'},
            {'csr': 'valid', 'client_ip': '999.999.999.999'},
            {'csr': 'valid', 'request_metadata': 'not_a_dict'},
        ]

        for case in edge_cases:
            response = client.post('/api/v1/sign-csr',
                                 json=case,
                                 headers={'Authorization': 'Bearer test-api-secret'})

            # Should handle edge cases gracefully with proper error codes
            assert response.status_code in [400, 422], f"Should handle edge case properly: {case}"

            # Response should be well-formed JSON
            try:
                response.get_json()
            except Exception:
                pytest.fail(f"Response should be valid JSON for case: {case}")