"""
Gunicorn entrypoint with optional TLS configuration.

This script serves as the Docker container entrypoint for the service. It reads
Gunicorn configuration from environment variables, optionally configures TLS by
calling the application's TLS setup utility, and then execs into Gunicorn.

The TLS integration works as follows:
    1. ``configure_tls_for_gunicorn()`` is called to check whether application-level
       TLS is enabled (via ENABLE_APPLICATION_TLS env var).
    2. If TLS is enabled, the returned dict provides ``certfile`` and ``keyfile``
       paths which are appended to GUNICORN_CMD_ARGS.
    3. If TLS is disabled (returns None), Gunicorn runs in plain HTTP mode.

Environment Variables:
    GUNICORN_CMD_ARGS: Additional Gunicorn CLI arguments (default: "").
    GUNICORN_LOG_LEVEL: Log level passed to ``--log-level`` (default: "info").
    FLASK_APP: The WSGI application module (default: "wsgi:application").

Security Considerations:
    - Uses ``os.execvp`` to replace the Python process with Gunicorn, ensuring
      proper signal handling and PID 1 behavior in containers.
    - Uses ``shlex.split`` for safe parsing of GUNICORN_CMD_ARGS to prevent
      shell injection via malformed environment variables.
"""

import os
import shlex


def main():
    """
    Build and exec the Gunicorn command with optional TLS arguments.

    Reads configuration from environment variables, checks for TLS settings
    via ``configure_tls_for_gunicorn()``, constructs the full Gunicorn command
    line, and replaces the current process with Gunicorn.

    Returns:
        This function does not return; it calls ``os.execvp()`` to replace
        the current process.

    Raises:
        OSError: If ``os.execvp`` fails (e.g., gunicorn not found on PATH).
    """
    from app.utils.tls_setup import configure_tls_for_gunicorn

    tls_config = configure_tls_for_gunicorn()

    gunicorn_cmd_args = os.environ.get('GUNICORN_CMD_ARGS', '')
    log_level = os.environ.get('GUNICORN_LOG_LEVEL', 'info')
    flask_app = os.environ.get('FLASK_APP', 'wsgi:application')

    if tls_config:
        gunicorn_cmd_args += f" --certfile {tls_config['certfile']} --keyfile {tls_config['keyfile']}"

    cmd = f"gunicorn --log-level {log_level} {flask_app} {gunicorn_cmd_args}"
    args = shlex.split(cmd)

    os.execvp(args[0], args)


if __name__ == '__main__':
    main()
