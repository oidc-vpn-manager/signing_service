# Signing Service for OIDC VPN Manager

The Signing Service is an isolated microservice responsible for all cryptographic operations within the OIDC VPN Manager system. This service ensures that private key materials are never exposed to the frontend tier, providing a secure separation of concerns for certificate generation and management.

## 🔐 Security Architecture

The signing service implements several critical security features:

1. **Key Isolation**: Certificate Authority private keys never leave this service
2. **API Authentication**: All requests require valid API tokens for service-to-service communication
3. **Automatic Audit Logging**: Every certificate issued is automatically logged to the Certificate Transparency service
4. **Secure Defaults**: Uses modern cryptographic standards and safe parameter choices

## 🚀 Key Features

### Certificate Generation
- **User Certificates**: Individual client certificates for VPN access with appropriate key usage extensions
- **Server Certificates**: OpenVPN server certificates with proper Subject Alternative Names (SANs)
- **Modern Cryptography**: Support for Ed25519 and RSA (2048/4096 bit) keys

### PKI Management
- **Intermediate CA Operations**: Signs all certificates using the intermediate CA private key
- **Passphrase Protection**: CA private keys are encrypted and require passphrase authentication
- **Certificate Chain Validation**: Ensures all issued certificates have proper trust chains

### Service Integration
- **Certificate Transparency Logging**: Automatic submission of all issued certificates for audit purposes
- **Health Monitoring**: Built-in health checks for monitoring and load balancing
- **Structured Logging**: JSON-formatted logs for security monitoring and operations

## 📊 API Endpoints

### Certificate Signing
- `POST /api/v1/sign`: Generate and sign certificates
- `GET /health`: Service health check endpoint

All API endpoints require authentication via shared secrets configured between services.

## 🔧 Configuration

### Environment Variables
- `INTERMEDIATE_CA_CERTIFICATE_FILE`: Path to intermediate CA certificate
- `INTERMEDIATE_CA_KEY_FILE`: Path to encrypted intermediate CA private key  
- `INTERMEDIATE_CA_KEY_PASSPHRASE_FILE`: Path to file containing CA key passphrase
- `SIGNING_SERVICE_API_SECRET_FILE`: Path to API authentication secret
- `CERTTRANSPARENCY_SERVICE_URL`: URL of Certificate Transparency service
- `CT_SERVICE_API_SECRET_FILE`: Path to CT service API secret

### PKI Setup
Use the included script to import PKI materials:
```bash
./import_pki.sh
```

This script safely copies and sets appropriate permissions on CA certificates and keys.

## 🧪 Testing

The service maintains comprehensive test coverage:

### Unit Tests
```bash
cd services/signing
python -m pytest tests/unit/ -v
```

### Integration Tests
```bash
python -m pytest tests/integration/ -v
```

### Functional Tests
```bash
python -m pytest tests/functional/ -v
```

All tests must maintain 100% code coverage and pass without errors.

## 📦 Deployment

### Docker Container
```bash
docker build -t oidc-vpn-manager/signing .
docker run -d --name signing-service \
  --env-file .env.signing \
  -v /path/to/pki:/pki:ro \
  oidc-vpn-manager/signing
```

### Kubernetes
Deploy using the Helm chart in `deploy/helm/oidc-vpn-manager/`.

## 🔍 Monitoring

### Health Checks
The service provides health check endpoints for monitoring:
- Service availability
- Database connectivity (if applicable)
- PKI material accessibility
- Certificate Transparency service connectivity

### Logging
Structured JSON logs include:
- Certificate generation events
- Authentication attempts
- Error conditions
- Performance metrics

### Metrics
Key metrics to monitor:
- Certificate generation rate
- Success/failure ratios
- Response times
- Resource utilization

## 🛡️ Security Considerations

### Network Security
- Deploy in isolated network segment
- Restrict access to CA private keys
- Use TLS for all inter-service communication
- Implement proper firewall rules

### Secret Management
- Use external secret management systems in production
- Rotate API secrets regularly
- Monitor secret access and usage
- Implement least-privilege access principles

### Operational Security
- Regular security updates for base images
- Monitor for certificate generation anomalies
- Implement proper backup and recovery procedures
- Maintain audit trails for all cryptographic operations

## 🤝 Contributing

Contributions are welcome! Since this is Free Software:

- No copyright assignment needed, but will be gratefully received
- **Feature requests and improvements are gratefully received**, however they may not be implemented due to time constraints or if they don't align with the developer's vision for the project
- Please ensure all tests pass and maintain 100% code coverage
- Follow existing security practices and patterns

### Development Standards
- All code must maintain 100% test coverage
- Security-first design principles
- Comprehensive documentation for all changes
- Regular security review of cryptographic operations

## 📄 License

This software is released under the [GNU Affero General Public License version 3](LICENSE).

## 🤖 AI Assistance Disclosure

This code was developed with assistance from AI tools. While released under a permissive license that allows unrestricted reuse, we acknowledge that portions of the implementation may have been influenced by AI training data. Should any copyright assertions or claims arise regarding uncredited imported code, the affected portions will be rewritten to remove or properly credit any unlicensed or uncredited work.