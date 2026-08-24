from __future__ import annotations

import argparse
import json

from .core import inspect_target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='packet-route-audit',
        description='Run safe DNS and TCP reachability checks.',
    )
    parser.add_argument('targets', nargs='+', help='host, host:port, or [IPv6]:port')
    parser.add_argument('--port', type=int, default=443, help='default TCP port')
    parser.add_argument('--timeout', type=float, default=2.0, help='TCP timeout in seconds')
    parser.add_argument('--json', action='store_true', help='emit JSON')
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    results = [inspect_target(t, args.port, args.timeout) for t in args.targets]
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for item in results:
            state = 'OK' if item['tcp']['ok'] else 'FAIL'
            addresses = ','.join(item['addresses']) or '-'
            print(f"{state:4} {item['host']}:{item['port']} dns={addresses} latency_ms={item['tcp']['latency_ms']}")
    return 0 if all(item['tcp']['ok'] for item in results) else 1


if __name__ == '__main__':
    raise SystemExit(main())
