import os
from app.utils.environment import loadConfigValueFromFileOrEnvironment, loadBoolConfigValue

class Config:
    """

    Configuration for the Signing Service
    """
    # Path to the Intermediate CA certificate
    INTERMEDIATE_CA_CERTIFICATE_FILE = os.environ.get('INTERMEDIATE_CA_CERTIFICATE_FILE', '/pki/intermediate-ca.crt')
    
    # Path to the Intermediate CA's encrypted private key
    INTERMEDIATE_CA_KEY_FILE = os.environ.get('INTERMEDIATE_CA_KEY_FILE', '/pki/intermediate-ca.key')

    # The passphrase to decrypt the Intermediate CA private key
    INTERMEDIATE_CA_KEY_PASSPHRASE = loadConfigValueFromFileOrEnvironment('INTERMEDIATE_CA_KEY_PASSPHRASE')

    # The shared secret used to authenticate requests from the Frontend Service
    SIGNING_SERVICE_API_SECRET = loadConfigValueFromFileOrEnvironment('SIGNING_SERVICE_API_SECRET')

    # Certificate Transparency Service Configuration
    CERTTRANSPARENCY_SERVICE_URL = os.environ.get('CERTTRANSPARENCY_SERVICE_URL', 'http://certtransparency:8800/api/v1')
    CT_SERVICE_API_SECRET = loadConfigValueFromFileOrEnvironment('CT_SERVICE_API_SECRET')
    CERTTRANSPARENCY_SERVICE_URL_TLS_VALIDATE = loadBoolConfigValue('CERTTRANSPARENCY_SERVICE_URL_TLS_VALIDATE', 'true')