"""
Integration tests for the V1 signing API.
"""
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

def test_sign_csr_success(client, app):
    """
    GIVEN a valid CSR and API secret
    WHEN a request is made to the /sign-csr endpoint
    THEN check that a valid, signed certificate is returned.
    """
    # Arrange: Create a new key and CSR to be signed
    client_key = ed25519.Ed25519PrivateKey.generate()
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "client.example.com")])
    ).sign(client_key, None)
    
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    api_secret = app.config['SIGNING_SERVICE_API_SECRET']
    
    # Act
    response = client.post(
        '/api/v1/sign-csr',
        headers={'Authorization': f'Bearer {api_secret}'},
        json={'csr': csr_pem}
    )

    # Assert
    assert response.status_code == 200
    assert 'certificate' in response.json
    
    # Verify the returned certificate
    cert_pem = response.json['certificate']
    received_cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
    assert received_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "client.example.com"
    assert received_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Test Intermediate CA"

def test_sign_csr_unauthorized(client):
    """
    GIVEN an invalid API secret
    WHEN a request is made to the /sign-csr endpoint
    THEN check that the request is rejected.
    """
    response = client.post(
        '/api/v1/sign-csr',
        headers={'Authorization': 'Bearer wrong-secret'},
        json={'csr': '...'}
    )
    assert response.status_code == 401

def test_sign_csr_bad_request(client, app):
    """
    GIVEN a valid API secret but a malformed request body
    WHEN a request is made to the /sign-csr endpoint
    THEN check that the request is rejected.
    """
    api_secret = app.config['SIGNING_SERVICE_API_SECRET']
    response = client.post(
        '/api/v1/sign-csr',
        headers={'Authorization': f'Bearer {api_secret}'},
        json={'wrong_key': '...'} # Missing 'csr' key
    )
    assert response.status_code == 400

def test_sign_csr_invalid_csr_format(client, app):
    """
    GIVEN a malformed CSR string
    WHEN a request is made to the /sign-csr endpoint
    THEN check that the service handles the error gracefully.
    """
    api_secret = app.config['SIGNING_SERVICE_API_SECRET']
    
    response = client.post(
        '/api/v1/sign-csr',
        headers={'Authorization': f'Bearer {api_secret}'},
        json={'csr': 'this-is-not-a-valid-csr'}
    )

    assert response.status_code == 400
    assert "Invalid CSR provided" in response.json['error']

def test_sign_csr_ca_files_not_found(client, app):
    """
    GIVEN that the intermediate CA files are missing
    WHEN a request is made to the /sign-csr endpoint
    THEN check that a 500 internal server error is returned.
    """
    # Arrange: Create a valid CSR and then point the config to a non-existent file
    client_key = ed25519.Ed25519PrivateKey.generate()
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "client.example.com")])
    ).sign(client_key, None)
    
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    api_secret = app.config['SIGNING_SERVICE_API_SECRET']
    app.config['INTERMEDIATE_CA_CERTIFICATE_FILE'] = '/non/existent/path.crt'

    # Act
    response = client.post(
        '/api/v1/sign-csr',
        headers={'Authorization': f'Bearer {api_secret}'},
        json={'csr': csr_pem}
    )
    
    # Assert
    assert response.status_code == 500
    assert "An internal error occurred" in response.json['error']


def test_sign_csr_with_successful_ct_logging(client, app):
    """
    GIVEN a valid CSR and mocked successful CT logging
    WHEN a request is made to the /sign-csr endpoint
    THEN check that certificate issuance succeeds and CT logging success is logged.
    """
    from unittest.mock import patch, Mock
    
    # Arrange: Create a new key and CSR to be signed
    client_key = ed25519.Ed25519PrivateKey.generate()
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "client.example.com")])
    ).sign(client_key, None)
    
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    api_secret = app.config['SIGNING_SERVICE_API_SECRET']
    
    # Mock successful CT logging
    with patch('app.routes.api.v1.log_certificate_to_ct') as mock_ct_log:
        mock_ct_log.return_value = {
            'status': 'logged',
            'certificate': {
                'fingerprint_sha256': 'abc123'
            }
        }
        
        # Act
        response = client.post(
            '/api/v1/sign-csr',
            headers={'Authorization': f'Bearer {api_secret}'},
            json={'csr': csr_pem}
        )

        # Assert
        assert response.status_code == 200
        assert 'certificate' in response.json
        
        # Verify CT logging was called
        mock_ct_log.assert_called_once()
        

def test_sign_csr_with_failed_ct_logging(client, app):
    """
    GIVEN a valid CSR and mocked failed CT logging
    WHEN a request is made to the /sign-csr endpoint  
    THEN check that certificate issuance still succeeds despite CT logging failure.
    """
    from unittest.mock import patch, Mock
    
    # Arrange: Create a new key and CSR to be signed
    client_key = ed25519.Ed25519PrivateKey.generate()
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "client.example.com")])
    ).sign(client_key, None)
    
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    api_secret = app.config['SIGNING_SERVICE_API_SECRET']
    
    # Mock failed CT logging (returns None)
    with patch('app.routes.api.v1.log_certificate_to_ct') as mock_ct_log:
        mock_ct_log.return_value = None
        
        # Act
        response = client.post(
            '/api/v1/sign-csr',
            headers={'Authorization': f'Bearer {api_secret}'},
            json={'csr': csr_pem}
        )

        # Assert  
        assert response.status_code == 200
        assert 'certificate' in response.json
        
        # Verify CT logging was called but failed
        mock_ct_log.assert_called_once()


def test_sign_csr_with_ct_logging_exception(client, app):
    """
    GIVEN a valid CSR and mocked CT logging that raises an exception
    WHEN a request is made to the /sign-csr endpoint
    THEN check that certificate issuance still succeeds despite CT logging exception.
    """
    from unittest.mock import patch, Mock
    
    # Arrange: Create a new key and CSR to be signed
    client_key = ed25519.Ed25519PrivateKey.generate()
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "client.example.com")])
    ).sign(client_key, None)
    
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    api_secret = app.config['SIGNING_SERVICE_API_SECRET']
    
    # Mock CT logging that raises an exception
    with patch('app.routes.api.v1.log_certificate_to_ct') as mock_ct_log:
        mock_ct_log.side_effect = Exception('CT service unavailable')
        
        # Act
        response = client.post(
            '/api/v1/sign-csr',
            headers={'Authorization': f'Bearer {api_secret}'},
            json={'csr': csr_pem}
        )

        # Assert
        assert response.status_code == 200
        assert 'certificate' in response.json
        
        # Verify CT logging was called but raised an exception
        mock_ct_log.assert_called_once()