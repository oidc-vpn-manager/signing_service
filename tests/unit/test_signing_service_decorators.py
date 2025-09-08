"""
Unit tests for the signing service decorators.
"""

import pytest
from flask import Flask, jsonify
from app.utils.decorators import frontend_api_secret_required

@pytest.fixture
def app():
    """Provides a Flask app for testing the decorator."""
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['SIGNING_SERVICE_API_SECRET'] = 'test-secret'

    @app.route('/protected')
    @frontend_api_secret_required
    def protected_route():
        return jsonify(status="success")

    return app

def test_secret_required_success(app):
    """
    Tests that a valid secret grants access.
    """
    client = app.test_client()
    response = client.get(
        '/protected',
        headers={'Authorization': 'Bearer test-secret'}
    )
    assert response.status_code == 200
    assert response.json['status'] == 'success'

def test_secret_required_invalid_secret(app):
    """
    Tests that an invalid secret is rejected.
    """
    client = app.test_client()
    response = client.get(
        '/protected',
        headers={'Authorization': 'Bearer wrong-secret'}
    )
    assert response.status_code == 401

def test_secret_required_missing_header(app):
    """
    Tests that a missing header is rejected.
    """
    client = app.test_client()
    response = client.get('/protected')
    assert response.status_code == 401

def test_secret_not_configured(app):
    """
    Tests that the endpoint returns a 500 error if the secret is not configured.
    """
    app.config['SIGNING_SERVICE_API_SECRET'] = None
    client = app.test_client()
    response = client.get(
        '/protected',
        headers={'Authorization': 'Bearer test-secret'}
    )
    assert response.status_code == 500