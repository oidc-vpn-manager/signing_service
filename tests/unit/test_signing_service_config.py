import pytest
from unittest.mock import patch
from importlib import reload

class TestConfigLoading:
    """
    Tests for the configuration of the Signing Service.
    """

    def test_load_from_environment_variable(self, monkeypatch):
        """
        Tests that a value is correctly loaded from an environment variable.
        """
        monkeypatch.setenv('SIGNING_SERVICE_API_SECRET', 'env_secret')
        # Use the full import path
        from app import config
        reload(config)
        assert config.Config.SIGNING_SERVICE_API_SECRET == 'env_secret'

    def test_load_from_file(self, monkeypatch, tmp_path):
        """
        Tests that a value is correctly loaded from a secret file.
        """
        file_path = tmp_path / "secret.txt"
        file_path.write_text("file_secret")
        monkeypatch.setenv('SIGNING_SERVICE_API_SECRET_FILE', str(file_path))

        from importlib import reload
        # Use the full import path
        from app import config
        reload(config)
        
        assert config.Config.SIGNING_SERVICE_API_SECRET == "file_secret"

    def test_load_from_nonexistent_file_raises_error(self, monkeypatch):
        """
        Tests that a FileNotFoundError is raised if the secret file path does not exist.
        """
        # Arrange: Set the _FILE variable to a path that does not exist
        monkeypatch.setenv('SECRET_THING_FILE', '/non/existent/path/secret.txt')
        
        from importlib import reload
        from app.utils import environment
        reload(environment)

        # Act & Assert
        with pytest.raises(FileNotFoundError):
            environment.loadConfigValueFromFileOrEnvironment('SECRET_THING')