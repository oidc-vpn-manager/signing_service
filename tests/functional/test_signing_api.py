import requests
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

def test_signing_endpoint_success(live_server):
    """
    GIVEN a running signing service with a loaded Intermediate CA
    WHEN a valid, authorized request is made with a CSR
    THEN a valid, signed certificate is returned.
    """
    api_secret = live_server.app.config['SIGNING_SERVICE_API_SECRET']
    
    client_key = ed25519.Ed25519PrivateKey.generate()
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "functional-test.client.com")])
    ).sign(client_key, None)
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    endpoint_url = f"{live_server.url()}/api/v1/sign-csr"
    headers = {'Authorization': f'Bearer {api_secret}'}
    payload = {'csr': csr_pem}
    
    response = requests.post(endpoint_url, headers=headers, json=payload)

    assert response.status_code == 200
    response_json = response.json()
    assert 'certificate' in response_json

    received_cert = x509.load_pem_x509_certificate(response_json['certificate'].encode('utf-8'))
    assert received_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "functional-test.client.com"
    assert received_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Test Intermediate CA"