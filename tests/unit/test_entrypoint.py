"""
Unit tests for the Gunicorn entrypoint script.

Tests verify that the entrypoint correctly constructs Gunicorn commands with
and without TLS configuration, and properly delegates to os.execvp for
process replacement.

Security Considerations:
    - Validates that TLS certificate and key paths are correctly appended
      to the Gunicorn command when TLS is enabled.
    - Confirms that no TLS arguments leak into the command when TLS is disabled.
    - Verifies shlex.split is used for safe argument parsing (implicitly
      tested via command structure validation).
"""

import os
import pytest
from unittest.mock import patch, MagicMock


class TestEntrypointMainTlsEnabled:
    """Tests for main() when TLS is enabled (configure_tls_for_gunicorn returns a dict)."""

    @patch('os.execvp')
    @patch('app.utils.tls_setup.configure_tls_for_gunicorn')
    def test_tls_args_appended_to_command(self, mock_tls, mock_execvp):
        """When TLS is enabled, --certfile and --keyfile are appended to the command."""
        mock_tls.return_value = {
            'certfile': '/app/tls/application.crt',
            'keyfile': '/app/tls/application.key',
        }
        env = {
            'GUNICORN_CMD_ARGS': '--bind=0.0.0.0:8500 --workers=2',
            'GUNICORN_LOG_LEVEL': 'info',
            'FLASK_APP': 'wsgi:app',
        }
        with patch.dict(os.environ, env, clear=False):
            import entrypoint
            entrypoint.main()

        mock_execvp.assert_called_once()
        args = mock_execvp.call_args
        cmd_args = args[0][1]

        assert cmd_args[0] == 'gunicorn'
        assert '--certfile' in cmd_args
        assert '/app/tls/application.crt' in cmd_args
        assert '--keyfile' in cmd_args
        assert '/app/tls/application.key' in cmd_args
        assert '--log-level' in cmd_args
        assert 'info' in cmd_args
        assert 'wsgi:app' in cmd_args

    @patch('os.execvp')
    @patch('app.utils.tls_setup.configure_tls_for_gunicorn')
    def test_tls_certfile_and_keyfile_are_adjacent(self, mock_tls, mock_execvp):
        """The --certfile value immediately follows --certfile flag, same for --keyfile."""
        mock_tls.return_value = {
            'certfile': '/tmp/tls/chain.crt',
            'keyfile': '/app/tls/application.key',
        }
        env = {
            'GUNICORN_CMD_ARGS': '--bind=0.0.0.0:8500',
            'GUNICORN_LOG_LEVEL': 'warning',
            'FLASK_APP': 'wsgi:app',
        }
        with patch.dict(os.environ, env, clear=False):
            import entrypoint
            entrypoint.main()

        cmd_args = mock_execvp.call_args[0][1]
        certfile_idx = cmd_args.index('--certfile')
        keyfile_idx = cmd_args.index('--keyfile')
        assert cmd_args[certfile_idx + 1] == '/tmp/tls/chain.crt'
        assert cmd_args[keyfile_idx + 1] == '/app/tls/application.key'


class TestEntrypointMainTlsDisabled:
    """Tests for main() when TLS is disabled (configure_tls_for_gunicorn returns None)."""

    @patch('os.execvp')
    @patch('app.utils.tls_setup.configure_tls_for_gunicorn')
    def test_no_tls_args_when_disabled(self, mock_tls, mock_execvp):
        """When TLS is disabled, no --certfile or --keyfile arguments appear."""
        mock_tls.return_value = None
        env = {
            'GUNICORN_CMD_ARGS': '--bind=0.0.0.0:8500 --workers=2',
            'GUNICORN_LOG_LEVEL': 'info',
            'FLASK_APP': 'wsgi:app',
        }
        with patch.dict(os.environ, env, clear=False):
            import entrypoint
            entrypoint.main()

        mock_execvp.assert_called_once()
        cmd_args = mock_execvp.call_args[0][1]
        assert '--certfile' not in cmd_args
        assert '--keyfile' not in cmd_args

    @patch('os.execvp')
    @patch('app.utils.tls_setup.configure_tls_for_gunicorn')
    def test_basic_command_structure_without_tls(self, mock_tls, mock_execvp):
        """The base gunicorn command is correctly formed without TLS."""
        mock_tls.return_value = None
        env = {
            'GUNICORN_CMD_ARGS': '--bind=0.0.0.0:8500',
            'GUNICORN_LOG_LEVEL': 'debug',
            'FLASK_APP': 'wsgi:app',
        }
        with patch.dict(os.environ, env, clear=False):
            import entrypoint
            entrypoint.main()

        cmd_args = mock_execvp.call_args[0][1]
        assert cmd_args[0] == 'gunicorn'
        assert '--log-level' in cmd_args
        assert 'debug' in cmd_args
        assert 'wsgi:app' in cmd_args
        assert '--bind=0.0.0.0:8500' in cmd_args


class TestEntrypointCommandConstruction:
    """Tests for proper command construction and argument handling."""

    @patch('os.execvp')
    @patch('app.utils.tls_setup.configure_tls_for_gunicorn')
    def test_execvp_called_with_gunicorn(self, mock_tls, mock_execvp):
        """os.execvp is called with 'gunicorn' as the executable."""
        mock_tls.return_value = None
        env = {
            'GUNICORN_CMD_ARGS': '',
            'GUNICORN_LOG_LEVEL': 'info',
            'FLASK_APP': 'wsgi:app',
        }
        with patch.dict(os.environ, env, clear=False):
            import entrypoint
            entrypoint.main()

        assert mock_execvp.call_args[0][0] == 'gunicorn'

    @patch('os.execvp')
    @patch('app.utils.tls_setup.configure_tls_for_gunicorn')
    def test_default_env_values(self, mock_tls, mock_execvp):
        """Default values are used when environment variables are not set."""
        mock_tls.return_value = None
        env_to_remove = ['GUNICORN_CMD_ARGS', 'GUNICORN_LOG_LEVEL', 'FLASK_APP']
        with patch.dict(os.environ, {}, clear=False):
            for key in env_to_remove:
                os.environ.pop(key, None)
            import entrypoint
            entrypoint.main()

        cmd_args = mock_execvp.call_args[0][1]
        assert 'gunicorn' == cmd_args[0]
        assert '--log-level' in cmd_args
        assert 'info' in cmd_args
        assert 'wsgi:application' in cmd_args

    @patch('os.execvp')
    @patch('app.utils.tls_setup.configure_tls_for_gunicorn')
    def test_complex_gunicorn_cmd_args_parsed_safely(self, mock_tls, mock_execvp):
        """GUNICORN_CMD_ARGS with multiple flags are parsed correctly via shlex.split."""
        mock_tls.return_value = None
        env = {
            'GUNICORN_CMD_ARGS': '--bind=0.0.0.0:8500 --workers=2 --access-logfile - --error-logfile -',
            'GUNICORN_LOG_LEVEL': 'info',
            'FLASK_APP': 'wsgi:app',
        }
        with patch.dict(os.environ, env, clear=False):
            import entrypoint
            entrypoint.main()

        cmd_args = mock_execvp.call_args[0][1]
        assert '--bind=0.0.0.0:8500' in cmd_args
        assert '--workers=2' in cmd_args
        assert '--access-logfile' in cmd_args
        assert '--error-logfile' in cmd_args

    @patch('os.execvp')
    @patch('app.utils.tls_setup.configure_tls_for_gunicorn')
    def test_execvp_first_arg_matches_argv0(self, mock_tls, mock_execvp):
        """The first argument to execvp matches argv[0] in the args list."""
        mock_tls.return_value = None
        env = {
            'GUNICORN_CMD_ARGS': '',
            'GUNICORN_LOG_LEVEL': 'info',
            'FLASK_APP': 'wsgi:app',
        }
        with patch.dict(os.environ, env, clear=False):
            import entrypoint
            entrypoint.main()

        executable = mock_execvp.call_args[0][0]
        argv = mock_execvp.call_args[0][1]
        assert executable == argv[0]
