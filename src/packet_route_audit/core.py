from __future__ import annotations

import socket
import time
from typing import Any


def parse_target(value: str, default_port: int = 443) -> tuple[str, int]:
    value = value.strip()
    if not value:
        raise ValueError('target must not be empty')

    if value.startswith('['):
        end = value.find(']')
        if end < 0:
            raise ValueError('invalid bracketed IPv6 target')
        host = value[1:end]
        rest = value[end + 1:]
        if not rest:
            return host, default_port
        if not rest.startswith(':') or not rest[1:].isdigit():
            raise ValueError('invalid target port')
        return host, int(rest[1:])

    if value.count(':') == 1:
        host, maybe_port = value.rsplit(':', 1)
        if host and maybe_port.isdigit():
            return host, int(maybe_port)

    return value, default_port


def resolve_host(host: str) -> list[str]:
    records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    seen: set[str] = set()
    addresses: list[str] = []
    for record in records:
        address = record[4][0]
        if address not in seen:
            seen.add(address)
            addresses.append(address)
    return addresses


def tcp_probe(host: str, port: int, timeout: float = 2.0) -> dict[str, Any]:
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return {
            'ok': True,
            'host': host,
            'port': port,
            'latency_ms': round((time.monotonic() - started) * 1000, 2),
            'error': None,
        }
    except OSError as exc:
        return {
            'ok': False,
            'host': host,
            'port': port,
            'latency_ms': round((time.monotonic() - started) * 1000, 2),
            'error': str(exc),
        }


def inspect_target(value: str, default_port: int = 443, timeout: float = 2.0) -> dict[str, Any]:
    host, port = parse_target(value, default_port)
    try:
        addresses = resolve_host(host)
    except OSError as exc:
        addresses = []
        dns_error = str(exc)
    else:
        dns_error = None

    probe = tcp_probe(host, port, timeout)
    return {
        'target': value,
        'host': host,
        'port': port,
        'addresses': addresses,
        'dns_error': dns_error,
        'tcp': probe,
    }
