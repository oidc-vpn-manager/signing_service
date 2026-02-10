# Signing Service

This file provides LLMs with guidance for working with the Signing Service component of OIDC VPN Manager.

## Service Overview

The Signing Service is a security-focused microservice responsible for all cryptographic operations within OIDC VPN Manager. It operates on port 8500 and ensures private key materials never leave the service boundary, providing secure certificate generation and management.

## Architecture

### Flask Application Structure
- `app/` - Main application directory
  - `routes/` - API route handlers
    - `api/` - Versioned API endpoints
      - `v1/` - Version 1 API implementation
  - `utils/` - Core utility modules
    - `ca_core.py` - Certificate authority operations
    - `cryptography.py` - Cryptographic utilities
    - `crl_generator.py` - Certificate revocation list generation
    - `ct_client.py` - Certificate transparency client
    - `certtransparency_client.py` - CT service integration
    - `decorators.py` - Authentication decorators
    - `environment.py` - Environment variable handling
    - `tls_setup.py` - Application-level TLS configuration and snakeoil cert generation
  - `config.py` - Application configuration
  - `swagger.yaml` - API documentation specification

### Security Architecture
- **Key Isolation**: CA private keys never exposed to other services
- **API Authentication**: All requests require valid shared secrets
- **Automatic Audit Logging**: Every certificate issued is logged to CT service
- **Passphrase Protection**: CA private keys are encrypted with passphrases

## Key Dependencies

- **Flask**: Lightweight web framework
- **cryptography**: Modern Python cryptography library
- **PyYAML**: Configuration file parsing
- **flask-swagger-ui**: API documentation
- **gunicorn**: Production WSGI server
- **requests**: HTTP client for service communication

## Development Workflow

### Local Development
```bash
cd services/signing

# Install dependencies
pip install -r requirements.txt

# Import PKI materials
./import_pki.sh

# Run with Flask development server
export FLASK_APP=app
flask run --port 8500

# Run with Gunicorn (production-like)
gunicorn wsgi:app --bind 0.0.0.0:8500
```

### Testing
```bash
# Unit tests
python -m pytest tests/unit/ -v

# Integration tests
python -m pytest tests/integration/ -v

# Functional tests
python -m pytest tests/functional/ -v

# All tests with coverage
python -m pytest tests/ --cov=app --cov-report=html
```

### PKI Setup
```bash
# Use the import script to set up PKI materials
./import_pki.sh

# This script:
# - Copies certificates and keys to correct locations
# - Sets appropriate file permissions (600 for keys)
# - Validates certificate chain integrity
```

## API Endpoints

### Certificate Operations
- `POST /api/v1/sign` - Generate and sign certificates
  - Supports user and server certificate generation
  - Automatic certificate transparency logging
  - Returns signed certificate and chain

### Health & Monitoring
- `GET /health` - Service health check
- `GET /api` - API documentation (Swagger UI)
- `GET /swagger.yaml` - OpenAPI specification

## Configuration

### Environment Variables
- `INTERMEDIATE_CA_CERTIFICATE_FILE` - Path to intermediate CA certificate
- `INTERMEDIATE_CA_KEY_FILE` - Path to encrypted intermediate CA private key
- `INTERMEDIATE_CA_KEY_PASSPHRASE_FILE` - Path to CA key passphrase file
- `SIGNING_SERVICE_API_SECRET_FILE` - API authentication secret file
- `CERTTRANSPARENCY_SERVICE_URL` - CT service URL for logging
- `CT_SERVICE_API_SECRET_FILE` - CT service API secret file

### Application-Level TLS

The service supports in-built TLS at the Gunicorn level, configured via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLE_APPLICATION_TLS` | `true` | Enable/disable TLS on the Gunicorn server |
| `APPLICATION_TLS_CERT` | `/app/tls/application.crt` | Path to TLS certificate |
| `APPLICATION_TLS_KEY` | `/app/tls/application.key` | Path to TLS private key |
| `APPLICATION_CA_CERT` | (empty) | Optional CA certificate for chain serving |
| `APPLICATION_TLS_CN` | container hostname | Common name for snakeoil cert |
| `APPLICATION_TLS_SAN` | container hostname | Comma-separated SANs for snakeoil cert |
| `CERTTRANSPARENCY_SERVICE_URL_TLS_VALIDATE` | `true` | Validate TLS for CT service calls |

**Snakeoil Certificates**: If `ENABLE_APPLICATION_TLS` is enabled but the cert/key files don't exist at the configured paths, the service auto-generates a self-signed EC P-256 certificate on startup. This requires writable paths at the cert/key locations (handled by emptyDir volume mount in Kubernetes).

**Chain Serving**: When `APPLICATION_CA_CERT` is set and the file exists, the server cert and CA cert are concatenated into a chain file at `/tmp/tls/chain.crt`, which is passed to Gunicorn's `--certfile`. This allows clients to validate the full certificate chain.

**Client TLS Verification**: When `CERTTRANSPARENCY_SERVICE_URL` uses `https://`, the `CERTTRANSPARENCY_SERVICE_URL_TLS_VALIDATE` setting controls whether the service verifies the CT service's TLS certificate. Set to `false` when using self-signed certificates between services.

**Startup**: The service uses `entrypoint.py` which calls `configure_tls_for_gunicorn()` from `app/utils/tls_setup.py`, then execs Gunicorn with appropriate `--certfile`/`--keyfile` arguments.

### PKI Configuration
The service requires proper PKI materials:
- **Root CA Certificate**: For trust chain validation
- **Intermediate CA Certificate**: Public certificate for signing
- **Intermediate CA Private Key**: Encrypted private key for operations
- **Passphrase File**: Secure passphrase for key decryption

## Certificate Operations

### Supported Certificate Types
- **User Certificates**: Client certificates for VPN access
  - Key usage: Digital signature, key encipherment
  - Extended key usage: Client authentication
- **Server Certificates**: OpenVPN server certificates
  - Key usage: Digital signature, key encipherment  
  - Extended key usage: Server authentication
  - Subject Alternative Names (SANs) support

### Cryptographic Standards
- **Ed25519**: Modern elliptic curve (recommended)
- **RSA 2048/4096**: Traditional RSA keys
- **Certificate validity**: Configurable periods
- **Modern extensions**: Proper X.509v3 extensions

## Security Features

### Access Control
- API authentication via shared secrets
- Request/response validation
- Rate limiting support (when integrated)
- Comprehensive audit logging

### Key Management
- Encrypted private keys with passphrase protection
- Secure key loading and caching
- Memory protection for sensitive operations
- Automatic key validation

### Certificate Transparency Integration
- Automatic logging of all issued certificates
- Failure handling for CT service unavailability
- Structured logging for audit trails
- Integration with external CT services

## Testing Standards

- **100% test coverage required**
- Unit tests for cryptographic operations
- Integration tests for CT service communication
- Functional tests for complete certificate workflows
- Security-focused test cases for key handling
- **Comprehensive security testing** including:
  - Red team attack simulation (CSR attacks, payload injection)
  - Blue team defensive validation (authentication, input validation)
  - Bug bounty vulnerability patterns (DoS, timing attacks, bypass attempts)
  - Real vulnerability discovery and remediation during development

## Common Operations

### Adding New Certificate Types
1. Extend certificate generation logic in `ca_core.py`
2. Add new API endpoints in `routes/api/v1/`
3. Update OpenAPI specification in `swagger.yaml`
4. Add comprehensive tests for new certificate type
5. Update CT logging for new certificate metadata

### Cryptographic Updates
1. Modify cryptographic operations in `utils/cryptography.py`
2. Update key generation and validation logic
3. Ensure backward compatibility for existing certificates
4. Add security-focused tests
5. Update documentation and examples

### Service Integration
1. Modify client communication in `utils/ct_client.py`
2. Add authentication and error handling
3. Implement retry logic for service failures
4. Add monitoring and logging for service calls
5. Test integration thoroughly

## Debugging & Monitoring

### Logging
- Structured JSON logging for production
- Certificate generation event logging
- Error tracking with detailed context
- Performance metrics for cryptographic operations

### Health Monitoring
- PKI material accessibility checks
- Certificate Transparency service connectivity
- Key loading and validation status
- Resource utilization monitoring

### Security Monitoring
- Failed authentication attempts
- Unusual certificate generation patterns
- Key access and usage patterns  
- Certificate transparency submission failures

## File Structure Notes

- `import_pki.sh` - PKI import and setup script
- `wsgi.py` - WSGI application entry point
- `entrypoint.py` - Python entrypoint for TLS-aware Gunicorn startup
- `Dockerfile` - Container build configuration
- `tests/` - Comprehensive test suite with security focus
- `.coveragerc` - Coverage configuration
- `pytest.ini` - Test runner configuration

## Security Considerations

### Network Security
- Deploy in isolated network segment
- Use TLS for all inter-service communication
- Implement proper firewall rules
- Monitor network access patterns

### Operational Security
- Regular security updates for dependencies
- Monitor certificate generation anomalies
- Implement backup and recovery procedures
- Maintain complete audit trails
- Plan for key rotation and certificate renewal

### Development Security
- Never log sensitive information (keys, passphrases)
- Use secure coding practices for cryptographic operations
- Implement proper error handling without information leakage
- Regular security reviews of cryptographic code