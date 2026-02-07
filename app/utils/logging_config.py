"""
Logging Configuration for OIDC VPN Manager Signing Service

This module configures structured JSON logging for the Signing service,
with separate loggers for security events, application events, and access logs.
All logs are formatted for SIEM compatibility.
"""

import logging
import logging.config
import json
import sys
from datetime import datetime, timezone
from typing import Dict, Any
from flask import request, g


class JSONFormatter(logging.Formatter):
    """
    Custom formatter that outputs logs in JSON format suitable for SIEM ingestion.
    """

    def format(self, record):
        """Format log record as JSON."""

        # Base log structure
        log_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'service': 'oidc-vpn-manager-signing',
            'version': '1.0',
        }

        # Add thread/process info
        if hasattr(record, 'process') and record.process:
            log_entry['process_id'] = record.process
        if hasattr(record, 'thread') and record.thread:
            log_entry['thread_id'] = record.thread

        # Add request context if available
        try:
            if request:
                log_entry['request_context'] = {
                    'method': request.method,
                    'path': request.path,
                    'remote_addr': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent', ''),
                }

                # Add request ID if available
                if hasattr(g, 'request_id'):
                    log_entry['request_id'] = g.request_id

        except RuntimeError:
            # Outside of request context
            pass

        # Add exception info if present
        if record.exc_info and record.exc_info != (None, None, None):
            try:
                exc_type, exc_value, exc_traceback = record.exc_info
                log_entry['exception'] = {
                    'type': exc_type.__name__ if exc_type else None,
                    'message': str(exc_value) if exc_value else None,
                    'traceback': self.formatException(record.exc_info) if exc_traceback else None
                }
            except (AttributeError, TypeError, ValueError):
                # Handle cases where exc_info is not a proper tuple
                log_entry['exception'] = {
                    'type': 'UnknownException',
                    'message': 'Exception information not available',
                    'traceback': None
                }

        # Add custom fields from the log record
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
                          'filename', 'module', 'lineno', 'funcName', 'created',
                          'msecs', 'relativeCreated', 'thread', 'threadName',
                          'processName', 'process', 'exc_info', 'exc_text',
                          'stack_info', 'getMessage']:
                log_entry[key] = value

        return json.dumps(log_entry, default=str)


class SecurityEventFilter(logging.Filter):
    """Filter that only allows security events through."""

    def filter(self, record):
        return record.name == 'security_events'


class ApplicationEventFilter(logging.Filter):
    """Filter that allows application events but excludes security events."""

    def filter(self, record):
        return record.name != 'security_events' and not record.name.startswith('gunicorn')


class AccessLogFilter(logging.Filter):
    """Filter for access logs."""

    def filter(self, record):
        return record.name.startswith('gunicorn.access')


def setup_logging(app_config: Dict[str, Any] = None) -> None:
    """
    Set up structured logging configuration.

    Args:
        app_config: Flask app configuration dict
    """

    # Skip custom logging setup during testing to preserve caplog functionality
    if app_config and app_config.get('TESTING'):
        return

    # Determine log level from config
    log_level = 'INFO'
    if app_config:
        if app_config.get('ENVIRONMENT') == 'development':
            log_level = 'DEBUG'
        elif app_config.get('ENVIRONMENT') == 'production':
            log_level = 'WARNING'

    # Logging configuration
    config = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'json': {
                '()': JSONFormatter,
            },
            'simple': {
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            }
        },
        'filters': {
            'security_events': {
                '()': SecurityEventFilter,
            },
            'application_events': {
                '()': ApplicationEventFilter,
            },
            'access_logs': {
                '()': AccessLogFilter,
            }
        },
        'handlers': {
            'security_events': {
                'class': 'logging.StreamHandler',
                'stream': sys.stdout,
                'formatter': 'json',
                'filters': ['security_events'],
                'level': 'INFO',
            },
            'application_events': {
                'class': 'logging.StreamHandler',
                'stream': sys.stdout,
                'formatter': 'json',
                'filters': ['application_events'],
                'level': log_level,
            },
            'access_logs': {
                'class': 'logging.StreamHandler',
                'stream': sys.stdout,
                'formatter': 'json',
                'filters': ['access_logs'],
                'level': 'INFO',
            },
            'console': {
                'class': 'logging.StreamHandler',
                'stream': sys.stdout,
                'formatter': 'simple',
                'level': 'ERROR',  # Only show errors on console in non-dev
            }
        },
        'loggers': {
            'security_events': {
                'handlers': ['security_events'],
                'level': 'INFO',
                'propagate': False,
            },
            'flask.app': {
                'handlers': ['application_events'],
                'level': log_level,
                'propagate': False,
            },
            'gunicorn.access': {
                'handlers': ['access_logs'],
                'level': 'INFO',
                'propagate': False,
            },
            'gunicorn.error': {
                'handlers': ['application_events'],
                'level': 'INFO',
                'propagate': False,
            },
            'app': {
                'handlers': ['application_events'],
                'level': log_level,
                'propagate': False,
            },
            'werkzeug': {
                'handlers': ['application_events'],
                'level': 'WARNING',  # Reduce werkzeug noise
                'propagate': False,
            }
        },
        'root': {
            'handlers': ['console'],
            'level': 'ERROR',
        }
    }

    # In development, also log to console with simple format
    if app_config and app_config.get('ENVIRONMENT') == 'development':
        config['handlers']['console']['level'] = 'DEBUG'
        config['loggers']['flask.app']['handlers'].append('console')
        config['loggers']['app']['handlers'].append('console')

    logging.config.dictConfig(config)


def add_request_id_middleware(app):
    """
    Add middleware to generate and track request IDs for correlation.
    """
    import uuid

    @app.before_request
    def before_request():
        g.request_id = str(uuid.uuid4())

    @app.after_request
    def after_request(response):
        if hasattr(g, 'request_id'):
            response.headers['X-Request-ID'] = g.request_id
        return response


def configure_security_logging(app):
    """
    Configure security logging for the Flask application.

    Args:
        app: Flask application instance
    """

    # Skip security logging setup during testing to preserve caplog functionality
    if app.config.get('TESTING'):
        return

    # Set up logging configuration
    setup_logging(app.config)

    # Add request ID middleware
    add_request_id_middleware(app)

    # Log application startup
    app.logger.info("Signing service startup", extra={
        'event_type': 'system_startup',
        'service': 'signing',
        'version': '1.0',
        'environment': app.config.get('ENVIRONMENT', 'unknown')
    })

    # Log unhandled exceptions
    @app.errorhandler(500)
    def log_internal_error(error):
        app.logger.error(f"Internal server error: {error}", exc_info=True)
        return "Internal Server Error", 500

    # Log 404 errors (potential scanning/probing)
    @app.errorhandler(404)
    def log_not_found(error):
        # Log 404s as they might indicate scanning/probing
        if request and request.path and not request.path.startswith('/static/'):
            app.logger.warning(f"404 Not Found: {request.method} {request.path}")

            # Check for suspicious patterns
            suspicious_patterns = [
                'admin', 'wp-admin', 'phpmyadmin', '.env', 'config',
                'backup', 'api/v2', 'api/v3', '../', '.git',
                'shell', 'cmd', 'exec'
            ]

            if any(pattern in request.path.lower() for pattern in suspicious_patterns):
                app.logger.warning("Suspicious path scanning detected", extra={
                    'event_type': 'suspicious_activity',
                    'activity_type': 'path_scanning',
                    'path': request.path,
                    'method': request.method,
                    'patterns_detected': [p for p in suspicious_patterns if p in request.path.lower()]
                })

        return "Not Found", 404

    app.logger.info("Security logging configured successfully")