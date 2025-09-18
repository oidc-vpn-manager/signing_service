"""
Tests for logging configuration functionality.

This module tests the logging configuration system including JSON formatting,
filters, error handlers, and security logging features.
"""

import pytest
import logging
import json
import sys
from unittest.mock import patch, MagicMock
from app.utils.logging_config import (
    JSONFormatter,
    SecurityEventFilter,
    ApplicationEventFilter,
    AccessLogFilter,
    setup_logging,
    configure_security_logging
)


class TestJSONFormatter:
    """Tests for the JSONFormatter class."""

    def test_format_basic_record(self):
        """Test basic log record formatting."""
        formatter = JSONFormatter()

        # Create a basic log record
        record = logging.LogRecord(
            name='test_logger',
            level=logging.INFO,
            pathname='/test/path.py',
            lineno=42,
            msg='Test message',
            args=(),
            exc_info=None
        )

        result = formatter.format(record)
        parsed = json.loads(result)

        assert parsed['level'] == 'INFO'
        assert parsed['logger'] == 'test_logger'
        assert parsed['message'] == 'Test message'
        assert parsed['service'] == 'openvpn-manager-signing'
        assert 'timestamp' in parsed

    def test_format_with_request_context_error(self):
        """Test formatting when request context access raises RuntimeError."""
        formatter = JSONFormatter()

        record = logging.LogRecord(
            name='test_logger',
            level=logging.INFO,
            pathname='/test/path.py',
            lineno=42,
            msg='Test message',
            args=(),
            exc_info=None
        )

        # Create a mock that raises RuntimeError when evaluated in boolean context
        class RequestMock:
            def __bool__(self):
                raise RuntimeError("Working outside of request context")

        with patch('app.utils.logging_config.request', RequestMock()):
            result = formatter.format(record)
            parsed = json.loads(result)

            # Should format successfully without request context
            assert parsed['message'] == 'Test message'
            assert 'request_context' not in parsed

    def test_format_with_malformed_exc_info(self):
        """Test formatting with malformed exception info."""
        formatter = JSONFormatter()

        record = logging.LogRecord(
            name='test_logger',
            level=logging.ERROR,
            pathname='/test/path.py',
            lineno=42,
            msg='Test error',
            args=(),
            exc_info=None
        )

        # Force the record to have malformed exc_info that will cause unpacking error
        record.exc_info = ("not", "a", "valid", "tuple")  # Too many values

        result = formatter.format(record)
        parsed = json.loads(result)

        # Should handle malformed exc_info gracefully
        assert parsed['message'] == 'Test error'
        assert parsed['exception']['type'] == 'UnknownException'
        assert parsed['exception']['message'] == 'Exception information not available'

    def test_format_with_valid_exception(self):
        """Test formatting with valid exception info."""
        formatter = JSONFormatter()

        try:
            raise ValueError("Test exception")
        except ValueError:
            record = logging.LogRecord(
                name='test_logger',
                level=logging.ERROR,
                pathname='/test/path.py',
                lineno=42,
                msg='Test error with exception',
                args=(),
                exc_info=sys.exc_info()
            )

            result = formatter.format(record)
            parsed = json.loads(result)

            assert parsed['message'] == 'Test error with exception'
            assert parsed['exception']['type'] == 'ValueError'
            assert parsed['exception']['message'] == 'Test exception'
            assert 'traceback' in parsed['exception']

    def test_format_with_custom_fields(self):
        """Test formatting with custom fields in log record."""
        formatter = JSONFormatter()

        record = logging.LogRecord(
            name='test_logger',
            level=logging.INFO,
            pathname='/test/path.py',
            lineno=42,
            msg='Test message',
            args=(),
            exc_info=None
        )

        # Add custom fields
        record.event_type = 'test_event'
        record.user_id = 'test_user'

        result = formatter.format(record)
        parsed = json.loads(result)

        assert parsed['event_type'] == 'test_event'
        assert parsed['user_id'] == 'test_user'


class TestLoggingFilters:
    """Tests for logging filter classes."""

    def test_security_event_filter(self):
        """Test SecurityEventFilter only allows security events."""
        filter_obj = SecurityEventFilter()

        # Security event record
        security_record = logging.LogRecord(
            name='security_events',
            level=logging.WARNING,
            pathname='/test/path.py',
            lineno=42,
            msg='Security event',
            args=(),
            exc_info=None
        )

        # Regular application record
        app_record = logging.LogRecord(
            name='app',
            level=logging.INFO,
            pathname='/test/path.py',
            lineno=42,
            msg='App event',
            args=(),
            exc_info=None
        )

        assert filter_obj.filter(security_record) is True
        assert filter_obj.filter(app_record) is False

    def test_application_event_filter(self):
        """Test ApplicationEventFilter excludes security and gunicorn events."""
        filter_obj = ApplicationEventFilter()

        # Regular application record
        app_record = logging.LogRecord(
            name='app',
            level=logging.INFO,
            pathname='/test/path.py',
            lineno=42,
            msg='App event',
            args=(),
            exc_info=None
        )

        # Security event record
        security_record = logging.LogRecord(
            name='security_events',
            level=logging.WARNING,
            pathname='/test/path.py',
            lineno=42,
            msg='Security event',
            args=(),
            exc_info=None
        )

        # Gunicorn record
        gunicorn_record = logging.LogRecord(
            name='gunicorn.error',
            level=logging.ERROR,
            pathname='/test/path.py',
            lineno=42,
            msg='Gunicorn error',
            args=(),
            exc_info=None
        )

        assert filter_obj.filter(app_record) is True
        assert filter_obj.filter(security_record) is False
        assert filter_obj.filter(gunicorn_record) is False

    def test_access_log_filter(self):
        """Test AccessLogFilter only allows gunicorn access logs."""
        filter_obj = AccessLogFilter()

        # Gunicorn access record
        access_record = logging.LogRecord(
            name='gunicorn.access',
            level=logging.INFO,
            pathname='/test/path.py',
            lineno=42,
            msg='Access log',
            args=(),
            exc_info=None
        )

        # Regular application record
        app_record = logging.LogRecord(
            name='app',
            level=logging.INFO,
            pathname='/test/path.py',
            lineno=42,
            msg='App event',
            args=(),
            exc_info=None
        )

        assert filter_obj.filter(access_record) is True
        assert filter_obj.filter(app_record) is False


class TestSetupLogging:
    """Tests for the setup_logging function."""

    def test_setup_logging_default(self):
        """Test setup_logging with default configuration."""
        with patch('logging.config.dictConfig') as mock_dict_config:
            setup_logging()

            # Should call dictConfig with default settings
            mock_dict_config.assert_called_once()
            config = mock_dict_config.call_args[0][0]

            # Verify default log level is INFO
            assert config['loggers']['app']['level'] == 'INFO'

    def test_setup_logging_development(self):
        """Test setup_logging with development environment."""
        app_config = {'ENVIRONMENT': 'development'}

        with patch('logging.config.dictConfig') as mock_dict_config:
            setup_logging(app_config)

            mock_dict_config.assert_called_once()
            config = mock_dict_config.call_args[0][0]

            # Verify development settings
            assert config['loggers']['app']['level'] == 'DEBUG'
            assert config['handlers']['console']['level'] == 'DEBUG'
            assert 'console' in config['loggers']['app']['handlers']

    def test_setup_logging_production(self):
        """Test setup_logging with production environment."""
        app_config = {'ENVIRONMENT': 'production'}

        with patch('logging.config.dictConfig') as mock_dict_config:
            setup_logging(app_config)

            mock_dict_config.assert_called_once()
            config = mock_dict_config.call_args[0][0]

            # Verify production settings
            assert config['loggers']['app']['level'] == 'WARNING'

    def test_setup_logging_skips_during_testing(self):
        """Test setup_logging skips configuration when TESTING is True."""
        app_config = {'TESTING': True}

        with patch('logging.config.dictConfig') as mock_dict_config:
            setup_logging(app_config)

            # Should not call dictConfig during testing
            mock_dict_config.assert_not_called()


class TestConfigureSecurityLogging:
    """Tests for the configure_security_logging function."""

    def test_configure_security_logging_basic(self):
        """Test basic security logging configuration."""
        from flask import Flask

        app = Flask(__name__)
        app.config['ENVIRONMENT'] = 'test'

        with patch('app.utils.logging_config.setup_logging') as mock_setup:
            configure_security_logging(app)

            # Should call setup_logging with app config
            mock_setup.assert_called_once_with(app.config)

    def test_error_handler_500(self):
        """Test 500 error handler logging."""
        from flask import Flask

        app = Flask(__name__)
        configure_security_logging(app)

        with app.test_client() as client:
            # Create a route that deliberately raises an exception
            @app.route('/test_error')
            def test_error():
                raise Exception("Test exception")

            # Test the 500 error handler
            response = client.get('/test_error')

            # Should return 500 Internal Server Error
            assert response.status_code == 500
            assert b"Internal Server Error" in response.data

    def test_error_handler_404_suspicious_path(self):
        """Test 404 error handler with suspicious path patterns."""
        from flask import Flask

        app = Flask(__name__)
        configure_security_logging(app)

        suspicious_paths = [
            '/admin/config',
            '/wp-admin/index.php',
            '/phpmyadmin/',
            '/.env',
            '/backup.sql',
            '/api/v2/users',
            '/shell.php',
            '/../etc/passwd'
        ]

        with app.test_client() as client:
            for path in suspicious_paths:
                response = client.get(path)

                # Should return 404 Not Found
                assert response.status_code == 404
                assert b"Not Found" in response.data

    def test_error_handler_404_normal_path(self):
        """Test 404 error handler with normal (non-suspicious) paths."""
        from flask import Flask

        app = Flask(__name__)
        configure_security_logging(app)

        normal_paths = [
            '/nonexistent',
            '/user/profile',
            '/static/missing.css',
            '/api/v1/missing'
        ]

        with app.test_client() as client:
            for path in normal_paths:
                response = client.get(path)

                # Should return 404 Not Found
                assert response.status_code == 404

    def test_request_id_middleware(self):
        """Test request ID middleware functionality."""
        from flask import Flask

        app = Flask(__name__)
        configure_security_logging(app)

        @app.route('/test')
        def test_route():
            return 'test'

        with app.test_client() as client:
            response = client.get('/test')

            # Should add X-Request-ID header
            assert 'X-Request-ID' in response.headers
            assert len(response.headers['X-Request-ID']) > 0

    def test_configure_security_logging_skips_during_testing(self):
        """Test configure_security_logging skips setup when TESTING is True."""
        from flask import Flask

        app = Flask(__name__)
        app.config['TESTING'] = True

        with patch('app.utils.logging_config.setup_logging') as mock_setup:
            with patch('app.utils.logging_config.add_request_id_middleware') as mock_middleware:
                configure_security_logging(app)

                # Should not call setup_logging or add middleware during testing
                mock_setup.assert_not_called()
                mock_middleware.assert_not_called()