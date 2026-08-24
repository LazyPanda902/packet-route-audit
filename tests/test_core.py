import socket

from packet_route_audit import core


def test_parse_target_with_port():
    assert core.parse_target('example.com:8443') == ('example.com', 8443)


def test_parse_target_ipv6():
    assert core.parse_target('[::1]:443') == ('::1', 443)


def test_resolve_host_deduplicates(monkeypatch):
    monkeypatch.setattr(
        core.socket,
        'getaddrinfo',
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.10', 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.10', 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('2001:db8::10', 0, 0, 0)),
        ],
    )
    assert core.resolve_host('example.test') == ['192.0.2.10', '2001:db8::10']


def test_tcp_probe_success(monkeypatch):
    class Connection:
        def __enter__(self):
            return self
        def __exit__(self, *_):
            return False
    monkeypatch.setattr(core.socket, 'create_connection', lambda *args, **kwargs: Connection())
    result = core.tcp_probe('example.test', 443, 0.1)
    assert result['ok'] is True
    assert result['error'] is None
