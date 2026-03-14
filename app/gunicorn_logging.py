import ipaddress
import logging
import re

from gunicorn.glogging import Logger

_KUBE_PROBE_RE = re.compile(r'^kube-probe/\d+\.\d+')

_RFC1918_NETWORKS = (
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
)


def _is_rfc1918(addr: str) -> bool:
    """Return True if addr is an RFC 1918 private address."""
    try:
        ip = ipaddress.ip_address(addr)
        return any(ip in net for net in _RFC1918_NETWORKS)
    except ValueError:
        return False


class CustomGunicornLogger(Logger):
    """
    Gunicorn logger that suppresses Kubernetes liveness/readiness probe
    requests from the access log.

    A request is suppressed when all three conditions hold:
      - Remote address is an RFC 1918 private address
      - Path is /health
      - User-Agent matches kube-probe/\\d+\\.\\d+
    """

    def setup(self, cfg):
        super().setup(cfg)
        app_logger = logging.getLogger('flask.app')
        for handler in self.error_log.handlers:
            app_logger.addHandler(handler)
        app_logger.setLevel(logging.DEBUG)

    def access(self, resp, req, environ, request_time):
        user_agent = environ.get('HTTP_USER_AGENT', '')
        remote_addr = environ.get('REMOTE_ADDR', '')

        if (
            req.method == 'GET'
            and req.path == '/health'
            and _KUBE_PROBE_RE.match(user_agent)
            and _is_rfc1918(remote_addr)
        ):
            return

        super().access(resp, req, environ, request_time)
