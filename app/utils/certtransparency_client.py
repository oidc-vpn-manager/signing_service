"""
Certificate Transparency client for the Signing Service.

Provides functionality to log issued certificates to the Certificate Transparency service.
"""

import requests
from typing import Dict, Optional, Any
from flask import current_app
from cryptography import x509
from cryptography.hazmat.primitives import serialization


class CTLogError(Exception):
    """Exception raised when Certificate Transparency logging fails."""
    pass


class CTLogClient:
    """Client for logging certificates to the Certificate Transparency service."""
    
    def __init__(self, base_url: Optional[str] = None, api_secret: Optional[str] = None, timeout: int = 30):
        """
        Initialize the Certificate Transparency logging client.
        
        Args:
            base_url: Base URL for the Certificate Transparency service.
                     If None, will use CERTTRANSPARENCY_SERVICE_URL from config.
            api_secret: API secret for authentication.
                       If None, will use CT_SERVICE_API_SECRET from config.
            timeout: Request timeout in seconds.
        """
        self.base_url = base_url or current_app.config.get(
            'CERTTRANSPARENCY_SERVICE_URL', 
            'http://certtransparency:8800/api/v1'
        )
        self.api_secret = api_secret or current_app.config.get('CT_SERVICE_API_SECRET')
        self.timeout = timeout
        from app.utils.environment import loadBoolConfigValue
        tls_validate = loadBoolConfigValue('CERTTRANSPARENCY_SERVICE_URL_TLS_VALIDATE', 'true')
        self.tls_verify = tls_validate if self.base_url.startswith('https://') else True

        if not self.api_secret:
            current_app.logger.warning(
                "CT_SERVICE_API_SECRET not configured - certificate logging will fail"
            )
    
    def log_certificate(
        self, 
        certificate_pem: str, 
        certificate_type: str,
        certificate_purpose: Optional[str] = None,
        requester_info: Optional[Dict[str, Any]] = None,
        issuing_user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Log a certificate to the Certificate Transparency service.
        
        Args:
            certificate_pem: PEM-encoded certificate data
            certificate_type: Type of certificate ('client', 'server', 'intermediate')
            certificate_purpose: Purpose/description of the certificate
            requester_info: Additional information about the certificate request
            issuing_user_id: User ID who requested the certificate (for tracking)
            
        Returns:
            Dict containing the CT service response
            
        Raises:
            CTLogError: If logging fails
        """
        if not self.api_secret:
            raise CTLogError("CT service API secret not configured")
        
        url = f"{self.base_url}/certificates"
        headers = {
            'Content-Type': 'application/json',
            'X-CT-API-Secret': self.api_secret
        }
        
        payload = {
            'certificate_pem': certificate_pem,
            'certificate_type': certificate_type
        }
        
        if certificate_purpose:
            payload['certificate_purpose'] = certificate_purpose
            
        if requester_info:
            payload['requester_info'] = requester_info
            
        if issuing_user_id:
            payload['issuing_user_id'] = issuing_user_id
        
        try:
            current_app.logger.debug(f"Logging certificate to CT service: {url}")
            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=self.timeout,
                verify=self.tls_verify
            )
            response.raise_for_status()

            result = response.json()
            current_app.logger.info(
                f"Certificate logged to CT service successfully: "
                f"fingerprint={result.get('certificate', {}).get('fingerprint_sha256', 'unknown')}"
            )
            return result

        except requests.RequestException as e:
            current_app.logger.error(f"Failed to log certificate to CT service: {e}")
            raise CTLogError(f"Failed to communicate with CT service: {e}")
        except ValueError as e:
            current_app.logger.error(f"Invalid JSON response from CT service: {e}")
            raise CTLogError(f"Invalid response from CT service: {e}")
    
    def get_certificate_by_fingerprint(self, fingerprint: str) -> Dict[str, Any]:
        """
        Get certificate details by fingerprint from the CT service.
        
        Args:
            fingerprint: SHA-256 fingerprint of the certificate
            
        Returns:
            Dict containing certificate details
            
        Raises:
            CTLogError: If request fails
        """
        if not self.api_secret:
            raise CTLogError("CT service API secret not configured")
        
        url = f"{self.base_url}/certificates/{fingerprint}"
        headers = {
            'Content-Type': 'application/json',
            'X-CT-API-Secret': self.api_secret
        }
        
        try:
            current_app.logger.debug(f"Getting certificate from CT service: {url}")
            response = requests.get(url, headers=headers, timeout=self.timeout, verify=self.tls_verify)
            response.raise_for_status()
            return response.json()
            
        except requests.RequestException as e:
            current_app.logger.error(f"Failed to get certificate from CT service: {e}")
            raise CTLogError(f"Failed to communicate with CT service: {e}")
        except ValueError as e:
            current_app.logger.error(f"Invalid JSON response from CT service: {e}")
            raise CTLogError(f"Invalid response from CT service: {e}")
    
    def revoke_certificate(self, fingerprint: str, reason: str, revoked_by: str) -> Dict[str, Any]:
        """
        Revoke a certificate in the CT service.
        
        Args:
            fingerprint: SHA-256 fingerprint of the certificate to revoke
            reason: Reason for revocation
            revoked_by: User ID who is performing the revocation
            
        Returns:
            Dict containing revocation response
            
        Raises:
            CTLogError: If revocation fails
        """
        if not self.api_secret:
            raise CTLogError("CT service API secret not configured")
        
        url = f"{self.base_url}/certificates/{fingerprint}/revoke"
        headers = {
            'Content-Type': 'application/json',
            'X-CT-API-Secret': self.api_secret
        }
        
        payload = {
            'reason': reason,
            'revoked_by': revoked_by
        }
        
        try:
            current_app.logger.debug(f"Revoking certificate in CT service: {url}")
            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=self.timeout,
                verify=self.tls_verify
            )
            response.raise_for_status()
            return response.json()

        except requests.RequestException as e:
            current_app.logger.error(f"Failed to revoke certificate in CT service: {e}")
            raise CTLogError(f"Failed to communicate with CT service: {e}")
        except ValueError as e:
            current_app.logger.error(f"Invalid JSON response from CT service: {e}")
            raise CTLogError(f"Invalid response from CT service: {e}")
    
    def bulk_revoke_user_certificates(self, user_id: str, reason: str, revoked_by: str) -> Dict[str, Any]:
        """
        Bulk revoke all active certificates for a specific user in the CT service.
        
        Args:
            user_id: User ID whose certificates should be revoked
            reason: Reason for revocation
            revoked_by: User ID who is performing the revocation
            
        Returns:
            Dict containing bulk revocation response
            
        Raises:
            CTLogError: If bulk revocation fails
        """
        if not self.api_secret:
            raise CTLogError("CT service API secret not configured")
        
        url = f"{self.base_url}/users/{user_id}/revoke-certificates"
        headers = {
            'Content-Type': 'application/json',
            'X-CT-API-Secret': self.api_secret
        }
        
        payload = {
            'reason': reason,
            'revoked_by': revoked_by
        }
        
        try:
            current_app.logger.debug(f"Bulk revoking certificates for user {user_id} in CT service: {url}")
            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=self.timeout,
                verify=self.tls_verify
            )
            response.raise_for_status()
            return response.json()

        except requests.RequestException as e:
            current_app.logger.error(f"Failed to bulk revoke certificates in CT service: {e}")
            raise CTLogError(f"Failed to communicate with CT service: {e}")
        except ValueError as e:
            current_app.logger.error(f"Invalid JSON response from CT service: {e}")
            raise CTLogError(f"Invalid response from CT service: {e}")


def log_certificate_to_ct(
    certificate: x509.Certificate,
    certificate_type: str,
    certificate_purpose: Optional[str] = None,
    requester_info: Optional[Dict[str, Any]] = None,
    issuing_user_id: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Convenience function to log a certificate to the CT service.
    
    Args:
        certificate: X.509 certificate object
        certificate_type: Type of certificate ('client', 'server', 'intermediate')
        certificate_purpose: Purpose/description of the certificate
        requester_info: Additional information about the certificate request
        issuing_user_id: User ID who requested the certificate (for tracking)
        
    Returns:
        Dict containing the CT service response, or None if logging fails
    """
    try:
        # Convert certificate to PEM format
        certificate_pem = certificate.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode('utf-8')
        
        # Create CT client and log the certificate
        client = CTLogClient()
        return client.log_certificate(
            certificate_pem=certificate_pem,
            certificate_type=certificate_type,
            certificate_purpose=certificate_purpose,
            requester_info=requester_info,
            issuing_user_id=issuing_user_id
        )
        
    except Exception as e:
        current_app.logger.error(f"Failed to log certificate to CT service: {e}")
        return None


def get_ct_client() -> CTLogClient:
    """
    Get a Certificate Transparency client instance.
    
    Returns:
        CTLogClient instance
    """
    return CTLogClient()