from flask import Flask
# Use the full import path
from app import create_app
from app.config import Config

def test_create_app():
    """
    Tests that the create_app factory returns a configured Flask app.
    """
    # Act
    app = create_app()

    # Assert
    assert isinstance(app, Flask)
    assert app.config['INTERMEDIATE_CA_CERTIFICATE_FILE'] == Config.INTERMEDIATE_CA_CERTIFICATE_FILE