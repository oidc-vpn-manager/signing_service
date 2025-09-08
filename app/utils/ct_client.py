"""
Certificate Transparency Service Client for CRL number management.

This client handles communication with the Certificate Transparency service
to obtain monotonically increasing CRL numbers as required by X.509 standards.
"""

import requests
import logging
from typing import Optional
from flask import current_app

logger = logging.getLogger(__name__)


class CTClientError(Exception):
    """Exception raised when CT service communication fails."""
    pass


class CTClient:
    """
    Client for communicating with Certificate Transparency service.
    
    Handles CRL number requests and other CT service operations needed
    by the signing service.
    """
    
    def __init__(self, ct_service_url: str, api_secret: str):
        """
        Initialize CT client.
        
        Args:
            ct_service_url (str): Base URL of CT service
            api_secret (str): API secret for authentication
        """
        self.ct_service_url = ct_service_url.rstrip('/')
        self.api_secret = api_secret
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_secret}',
            'Content-Type': 'application/json',
            'User-Agent': 'OpenVPN-Signing-Service/1.0'
        })
    
    def get_next_crl_number(self, issuer_identifier: str) -> int:
        """
        Get the next CRL number for the given issuer.
        
        Args:
            issuer_identifier (str): Identifier for the CA issuer (usually CN)
            
        Returns:
            int: Next monotonically increasing CRL number
            
        Raises:
            CTClientError: If the CT service request fails
        """
        url = f"{self.ct_service_url}/api/v1/crl/next-number"
        payload = {'issuer_identifier': issuer_identifier}
        
        try:
            logger.info(f"Requesting next CRL number for issuer: {issuer_identifier}")
            response = self.session.post(url, json=payload, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                crl_number = data['crl_number']
                logger.info(f"Received CRL number {crl_number} for issuer {issuer_identifier}")
                return crl_number
            else:
                error_msg = f"CT service returned {response.status_code}: {response.text}"
                logger.error(error_msg)
                raise CTClientError(error_msg)
                
        except requests.exceptions.RequestException as e:
            error_msg = f"Failed to communicate with CT service: {e}"
            logger.error(error_msg)
            raise CTClientError(error_msg)
    
    def get_current_crl_number(self, issuer_identifier: str) -> int:
        """
        Get the current CRL number for the given issuer without incrementing.
        
        Args:
            issuer_identifier (str): Identifier for the CA issuer
            
        Returns:
            int: Current CRL number (0 if no CRL has been issued yet)
            
        Raises:
            CTClientError: If the CT service request fails
        """
        url = f"{self.ct_service_url}/api/v1/crl/current-number/{issuer_identifier}"
        
        try:
            logger.info(f"Requesting current CRL number for issuer: {issuer_identifier}")
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                current_number = data['current_crl_number']
                logger.info(f"Current CRL number is {current_number} for issuer {issuer_identifier}")
                return current_number
            else:
                error_msg = f"CT service returned {response.status_code}: {response.text}"
                logger.error(error_msg)
                raise CTClientError(error_msg)
                
        except requests.exceptions.RequestException as e:
            error_msg = f"Failed to communicate with CT service: {e}"
            logger.error(error_msg)
            raise CTClientError(error_msg)


def get_ct_client() -> CTClient:
    """
    Get a configured CT client instance.
    
    Returns:
        CTClient: Configured client instance
        
    Raises:
        CTClientError: If CT service is not properly configured
    """
    ct_service_url = current_app.config.get('CERTTRANSPARENCY_SERVICE_URL')
    api_secret = current_app.config.get('CT_SERVICE_API_SECRET')
    
    if not ct_service_url:
        raise CTClientError("CERTTRANSPARENCY_SERVICE_URL is not configured")
    
    if not api_secret:
        raise CTClientError("CT_SERVICE_API_SECRET is not configured")
    
    return CTClient(ct_service_url, api_secret)