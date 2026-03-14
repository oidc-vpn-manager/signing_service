"""
Tests for CustomGunicornLogger — Kubernetes probe suppression logic.
"""

import pytest
from unittest.mock import MagicMock, patch

from app.gunicorn_logging import CustomGunicornLogger, _is_rfc1918


# ---------------------------------------------------------------------------
# _is_rfc1918 helper
# ---------------------------------------------------------------------------

class TestIsRfc1918:
    def test_10_block(self):
        assert _is_rfc1918('10.0.0.1')
        assert _is_rfc1918('10.255.255.255')

    def test_172_block(self):
        assert _is_rfc1918('172.16.0.1')
        assert _is_rfc1918('172.31.255.255')

    def test_192_168_block(self):
        assert _is_rfc1918('192.168.0.1')
        assert _is_rfc1918('192.168.255.255')

    def test_public_address(self):
        assert not _is_rfc1918('8.8.8.8')
        assert not _is_rfc1918('203.0.113.1')

    def test_172_15_not_rfc1918(self):
        assert not _is_rfc1918('172.15.255.255')

    def test_172_32_not_rfc1918(self):
        assert not _is_rfc1918('172.32.0.0')

    def test_invalid_address_returns_false(self):
        assert not _is_rfc1918('not-an-ip')
        assert not _is_rfc1918('')


# ---------------------------------------------------------------------------
# CustomGunicornLogger.access
# ---------------------------------------------------------------------------

def _make_logger():
    """Return a CustomGunicornLogger with Gunicorn internals stubbed out."""
    cfg = MagicMock()
    logger = CustomGunicornLogger.__new__(CustomGunicornLogger)
    logger.error_log = MagicMock()
    logger.error_log.handlers = []
    logger.access_log = MagicMock()
    logger.cfg = cfg
    return logger


def _make_environ(user_agent='', remote_addr='10.0.0.1'):
    return {'HTTP_USER_AGENT': user_agent, 'REMOTE_ADDR': remote_addr}


def _make_req(path='/health', method='GET'):
    req = MagicMock()
    req.path = path
    req.method = method
    return req


class TestAccessSuppression:
    def test_suppresses_kube_probe_from_rfc1918(self):
        """All three conditions met → no log."""
        logger = _make_logger()
        req = _make_req('/health', 'GET')
        environ = _make_environ('kube-probe/1.28', '10.0.0.5')

        with patch.object(CustomGunicornLogger, 'access', wraps=logger.access) as _:
            with patch('gunicorn.glogging.Logger.access') as mock_super:
                logger.access(MagicMock(), req, environ, 0)
                mock_super.assert_not_called()

    def test_passes_through_public_ip(self):
        """Public IP → logged even if path and UA match."""
        logger = _make_logger()
        req = _make_req('/health', 'GET')
        environ = _make_environ('kube-probe/1.28', '8.8.8.8')

        with patch('gunicorn.glogging.Logger.access') as mock_super:
            logger.access(MagicMock(), req, environ, 0)
            mock_super.assert_called_once()

    def test_passes_through_wrong_path(self):
        """/healthz or /other → logged even if UA and IP match."""
        logger = _make_logger()
        req = _make_req('/healthz', 'GET')
        environ = _make_environ('kube-probe/1.28', '10.0.0.5')

        with patch('gunicorn.glogging.Logger.access') as mock_super:
            logger.access(MagicMock(), req, environ, 0)
            mock_super.assert_called_once()

    def test_passes_through_wrong_user_agent(self):
        """UA doesn't match → logged."""
        logger = _make_logger()
        req = _make_req('/health', 'GET')
        environ = _make_environ('Mozilla/5.0', '10.0.0.5')

        with patch('gunicorn.glogging.Logger.access') as mock_super:
            logger.access(MagicMock(), req, environ, 0)
            mock_super.assert_called_once()

    def test_passes_through_non_get_method(self):
        """POST /health from probe UA → logged."""
        logger = _make_logger()
        req = _make_req('/health', 'POST')
        environ = _make_environ('kube-probe/1.28', '10.0.0.5')

        with patch('gunicorn.glogging.Logger.access') as mock_super:
            logger.access(MagicMock(), req, environ, 0)
            mock_super.assert_called_once()

    def test_ua_must_match_version_pattern(self):
        """kube-probe without version digits → logged."""
        logger = _make_logger()
        req = _make_req('/health', 'GET')
        environ = _make_environ('kube-probe/', '192.168.1.1')

        with patch('gunicorn.glogging.Logger.access') as mock_super:
            logger.access(MagicMock(), req, environ, 0)
            mock_super.assert_called_once()

    def test_suppresses_172_16_address(self):
        logger = _make_logger()
        req = _make_req('/health', 'GET')
        environ = _make_environ('kube-probe/1.30', '172.20.0.1')

        with patch('gunicorn.glogging.Logger.access') as mock_super:
            logger.access(MagicMock(), req, environ, 0)
            mock_super.assert_not_called()

    def test_suppresses_192_168_address(self):
        logger = _make_logger()
        req = _make_req('/health', 'GET')
        environ = _make_environ('kube-probe/1.30', '192.168.10.10')

        with patch('gunicorn.glogging.Logger.access') as mock_super:
            logger.access(MagicMock(), req, environ, 0)
            mock_super.assert_not_called()


class TestSetup:
    def test_setup_adds_handlers_to_flask_logger(self):
        """setup() forwards Gunicorn handlers to the flask.app logger."""
        import logging
        cfg = MagicMock()
        logger = CustomGunicornLogger.__new__(CustomGunicornLogger)
        fake_handler = MagicMock(spec=logging.Handler)
        logger.error_log = MagicMock()
        logger.error_log.handlers = [fake_handler]
        logger.access_log = MagicMock()
        logger.cfg = cfg

        with patch('gunicorn.glogging.Logger.setup'):
            logger.setup(cfg)

        flask_logger = logging.getLogger('flask.app')
        assert fake_handler in flask_logger.handlers
        assert flask_logger.level == logging.DEBUG
