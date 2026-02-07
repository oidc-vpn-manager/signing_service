import os
from flask import Flask, send_from_directory, Blueprint, jsonify
from flask_swagger_ui import get_swaggerui_blueprint

def create_app():
    """
    Creates the Flask application for the Signing Service.
    """
    app = Flask(__name__)
    app.config.from_object('app.config.Config')

    bp = Blueprint('health', __name__)

    @bp.route('/health')
    def health_check():
        return jsonify({
            'status': 'healthy',
            'service': 'signing',
            'version': '1.0.0'
        }), 200

    app.register_blueprint(bp)
    
    from .routes import api_bp
    app.register_blueprint(api_bp)

    SWAGGER_URL = '/api'
    API_URL = '/swagger.yaml'

    swaggerui_blueprint = get_swaggerui_blueprint(
        SWAGGER_URL,
        API_URL,
        config={
            'app_name': "OIDC VPN Manager Signing API"
        }
    )

    app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

    @app.route(API_URL)
    def swagger_spec():
        return send_from_directory(os.path.dirname(os.path.abspath(__file__)), 'swagger.yaml')

    # Configure structured security logging
    from app.utils.logging_config import configure_security_logging
    configure_security_logging(app)

    return app