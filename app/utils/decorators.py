"""
Defines decorators for the signing service.
"""

from functools import wraps
from flask import request, abort, current_app

def frontend_api_secret_required(f):
    """
    Decorator to protect routes with a shared secret from the frontend.
    Expects 'Authorization: Bearer <secret>' header.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        expected_secret = current_app.config.get('SIGNING_SERVICE_API_SECRET')
        if not expected_secret:
            # Abort if the secret is not configured on the server, a critical misconfiguration.
            abort(500, description="API secret not configured.")

        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            abort(401, description="Authorization header is missing or invalid.")
        
        sent_secret = auth_header.split('Bearer ')[1]
        
        # Use constant-time comparison to prevent timing attacks
        import hmac
        if not hmac.compare_digest(sent_secret.encode('utf-8'), expected_secret.encode('utf-8')):
            abort(401, description="Unauthorized: Invalid secret.")
        
        return f(*args, **kwargs)

    return decorated_function