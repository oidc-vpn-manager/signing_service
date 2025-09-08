from flask import Blueprint, jsonify, request, current_app
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app.utils.decorators import frontend_api_secret_required
from app.utils.cryptography import load_intermediate_ca
from app.utils.ca_core import sign_csr
from app.utils.certtransparency_client import log_certificate_to_ct, get_ct_client, CTLogError
from app.utils.crl_generator import CRLGenerator

bp = Blueprint('v1', __name__, url_prefix='/v1')

@bp.route('/sign-csr', methods=['POST'])
@frontend_api_secret_required
def sign_certificate_request():
    """
    Accepts a PEM-encoded CSR, signs it with the Intermediate CA,
    and returns the new certificate.
    """
    # 1. Validate the incoming request body
    data = request.get_json()
    if not data or 'csr' not in data:
        current_app.logger.warning("Request failed: missing 'csr' field in JSON body.")
        return jsonify(error="Request body must be JSON and contain a 'csr' field."), 400
    
    csr_pem = data['csr'].encode('utf-8')
    user_id = data.get('user_id')  # Extract user_id for certificate tracking
    certificate_type = data.get('certificate_type', 'client')  # Default to 'client' if not specified
    client_ip = data.get('client_ip')  # Extract client IP from frontend
    current_app.logger.debug(f"Certificate signing request - user_id: {user_id}, certificate_type: {certificate_type}")

    try:
        # 2. Load the CSR from the provided PEM data
        csr = x509.load_pem_x509_csr(csr_pem)
        current_app.logger.debug(f"Successfully loaded CSR for subject: {csr.subject}")

        # 3. Load the online Intermediate CA to act as the issuer
        current_app.logger.debug("Loading Intermediate CA...")
        issuer_key, issuer_cert = load_intermediate_ca()
        current_app.logger.debug("Intermediate CA loaded successfully.")

        # 4. Sign the CSR to create the new certificate
        current_app.logger.debug("Signing new certificate...")
        new_cert = sign_csr(csr=csr, issuer_cert=issuer_cert, issuer_key=issuer_key)
        current_app.logger.debug(f"Successfully signed new certificate for: {new_cert.subject}")

        # 5. Serialize the new certificate to PEM format for the response
        cert_pem = new_cert.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')

        # 6. Log the certificate to the Certificate Transparency service
        try:
            # Extract subject common name for purpose
            subject_cn = new_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            if certificate_type == 'server':
                certificate_purpose = f"Server certificate for {subject_cn}"
            else:
                certificate_purpose = f"User certificate for {subject_cn}"
            
            # Extract requester information - use client IP passed from frontend if available
            # Otherwise fall back to the signing service's request info
            original_client_ip = client_ip or request.remote_addr
            if not client_ip and request.headers.get('X-Forwarded-For'):
                # Take the first IP from the X-Forwarded-For chain (original client)
                forwarded_ips = request.headers.get('X-Forwarded-For').split(',')
                if forwarded_ips:
                    original_client_ip = forwarded_ips[0].strip()
            
            requester_info = {
                'issued_by': 'signing-service',
                'request_source': original_client_ip or 'unknown',
                'user_agent': request.headers.get('User-Agent', 'unknown')
            }
            
            # Log to Certificate Transparency service
            ct_result = log_certificate_to_ct(
                certificate=new_cert,
                certificate_type=certificate_type,
                certificate_purpose=certificate_purpose,
                requester_info=requester_info,
                issuing_user_id=user_id
            )
            
            if ct_result:
                current_app.logger.info(
                    f"Certificate logged to CT service: "
                    f"fingerprint={ct_result.get('certificate', {}).get('fingerprint_sha256', 'unknown')}"
                )
            else:
                current_app.logger.warning(
                    f"Failed to log certificate to CT service for {subject_cn}"
                )
                
        except Exception as e:
            # Don't fail the certificate issuance if CT logging fails
            current_app.logger.error(
                f"Certificate transparency logging failed for {new_cert.subject.rfc4514_string()}: {e}"
            )

        current_app.logger.info(f"Successfully issued certificate for {new_cert.subject.rfc4514_string()}")
        return jsonify(certificate=cert_pem), 200

    except ValueError as e:
        current_app.logger.error(f"Failed to process CSR: {e}")
        return jsonify(error=f"Invalid CSR provided: {e}"), 400
    except Exception as e:
        current_app.logger.critical(f"An unexpected internal error occurred: {e}", exc_info=True)
        return jsonify(error=f"An internal error occurred: {e}"), 500


@bp.route('/generate-crl', methods=['POST'])
@frontend_api_secret_required  
def generate_crl():
    """
    Generate a Certificate Revocation List (CRL) based on provided revoked certificates.
    Frontend service calls this with a list of revoked certificates from CT service.
    """
    data = request.get_json()
    if not data:
        return jsonify(error="Request body must be JSON"), 400
    
    revoked_certificates = data.get('revoked_certificates', [])
    next_update_hours = data.get('next_update_hours', 24)
    
    try:
        current_app.logger.info(f"Generating CRL for {len(revoked_certificates)} revoked certificates")
        
        # Load CA materials (reuse the existing signing service utilities)
        issuer_key, issuer_cert = load_intermediate_ca()
        
        # Convert CA materials to PEM strings for CRL generator
        ca_cert_pem = issuer_cert.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
        ca_key_pem = issuer_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        # Initialize CRL generator and load CA materials  
        crl_generator = CRLGenerator()
        crl_generator.load_ca_materials(ca_cert_pem, ca_key_pem, '')  # No passphrase needed for decrypted key
        
        # Generate the CRL
        crl_data = crl_generator.create_crl(revoked_certificates, next_update_hours)
        
        current_app.logger.info(f"Successfully generated CRL with {len(revoked_certificates)} entries")
        
        return crl_data, 200, {
            'Content-Type': 'application/pkix-crl',
            'Content-Disposition': 'attachment; filename="certificate-revocation-list.crl"',
            'Cache-Control': f'public, max-age={next_update_hours * 3600}',
            'Access-Control-Allow-Origin': '*'
        }
        
    except Exception as e:
        current_app.logger.error(f"Failed to generate CRL: {e}", exc_info=True)
        return jsonify(error=f"Failed to generate CRL: {e}"), 500


@bp.route('/revoke-certificate', methods=['POST'])
@frontend_api_secret_required
def revoke_certificate():
    """
    Revoke a certificate by its fingerprint.
    This endpoint is called by the Frontend service to revoke certificates.
    The revocation is logged to the Certificate Transparency service.
    """
    data = request.get_json()
    if not data:
        return jsonify(error="Request body must be JSON"), 400
    
    fingerprint = data.get('fingerprint')
    reason = data.get('reason')
    revoked_by = data.get('revoked_by')
    
    if not all([fingerprint, reason, revoked_by]):
        return jsonify(error="Missing required fields: fingerprint, reason, revoked_by"), 400
    
    # Validate revocation reason
    valid_reasons = [
        'key_compromise', 'ca_compromise', 'affiliation_changed',
        'superseded', 'cessation_of_operation', 'certificate_hold',
        'remove_from_crl', 'privilege_withdrawn', 'aa_compromise'
    ]
    
    if reason not in valid_reasons:
        return jsonify(error=f'Invalid revocation reason. Must be one of: {", ".join(valid_reasons)}'), 400
    
    try:
        # Log the revocation to Certificate Transparency service
        client = get_ct_client()
        
        # First check if certificate exists and get its details
        try:
            cert_response = client.get_certificate_by_fingerprint(fingerprint)
            certificate = cert_response.get('certificate')
            
            if not certificate:
                return jsonify(error='Certificate not found'), 404
                
            # Check if already revoked
            if certificate.get('revoked_at') or certificate.get('revocation'):
                return jsonify(error='Certificate is already revoked'), 400
                
        except CTLogError as e:
            if 'not found' in str(e).lower():
                return jsonify(error='Certificate not found'), 404
            else:
                raise
        
        # Log the revocation to CT service
        revocation_result = client.revoke_certificate(
            fingerprint=fingerprint,
            reason=reason,
            revoked_by=revoked_by
        )
        
        current_app.logger.info(
            f"Certificate {fingerprint} successfully revoked by {revoked_by} "
            f"with reason: {reason}"
        )
        
        return jsonify({
            'status': 'success',
            'message': 'Certificate revoked successfully',
            'certificate_fingerprint': fingerprint,
            'revocation_reason': reason,
            'revoked_by': revoked_by
        }), 200
        
    except CTLogError as e:
        current_app.logger.error(f"Certificate Transparency service error during revocation: {e}")
        return jsonify(error='Certificate Transparency service unavailable'), 503
    
    except Exception as e:
        current_app.logger.error(f"Unexpected error during certificate revocation: {e}", exc_info=True)
        return jsonify(error='Internal server error'), 500


@bp.route('/bulk-revoke-user-certificates', methods=['POST'])
@frontend_api_secret_required
def bulk_revoke_user_certificates():
    """
    Bulk revoke all active certificates for a specific user.
    This endpoint is called by the Frontend service for admin bulk revocations.
    """
    data = request.get_json()
    if not data:
        return jsonify(error="Request body must be JSON"), 400
    
    user_id = data.get('user_id')
    reason = data.get('reason')
    revoked_by = data.get('revoked_by')
    
    if not all([user_id, reason, revoked_by]):
        return jsonify(error="Missing required fields: user_id, reason, revoked_by"), 400
    
    # Validate revocation reason
    valid_reasons = [
        'key_compromise', 'ca_compromise', 'affiliation_changed',
        'superseded', 'cessation_of_operation', 'certificate_hold',
        'remove_from_crl', 'privilege_withdrawn', 'aa_compromise'
    ]
    
    if reason not in valid_reasons:
        return jsonify(error=f'Invalid revocation reason. Must be one of: {", ".join(valid_reasons)}'), 400
    
    try:
        # Use the CT service to perform bulk revocation
        client = get_ct_client()
        
        # Call CT service bulk revoke endpoint
        bulk_result = client.bulk_revoke_user_certificates(
            user_id=user_id,
            reason=reason,
            revoked_by=revoked_by
        )
        
        revoked_count = bulk_result.get('revoked_count', 0)
        
        current_app.logger.info(
            f"Bulk certificate revocation completed by {revoked_by}: "
            f"{revoked_count} certificates revoked for user {user_id} "
            f"with reason: {reason}"
        )
        
        return jsonify({
            'status': 'success',
            'message': f'Successfully revoked {revoked_count} certificates for user {user_id}',
            'user_id': user_id,
            'revoked_count': revoked_count,
            'reason': reason,
            'revoked_by': revoked_by
        }), 200
        
    except CTLogError as e:
        current_app.logger.error(f"Certificate Transparency service error during bulk revocation: {e}")
        return jsonify(error='Certificate Transparency service unavailable'), 503
    
    except Exception as e:
        current_app.logger.error(f"Unexpected error during bulk certificate revocation: {e}", exc_info=True)
        return jsonify(error='Internal server error'), 500