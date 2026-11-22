"""Explicitly started lab-only web content and synthetic canary collector."""
import argparse
import ipaddress
import json
from http.server import ThreadingHTTPServer
from pathlib import Path
import sys
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from testing.web_fixture import WebFixture, handler_for


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--state-dir", type=Path, required=True)
    init.add_argument("--origin", required=True)
    init.add_argument("--condition", choices=["control", "attack"], required=True)
    init.add_argument("--target-id", default="dvaa-researchbot")
    init.add_argument("--expected-target-ip", required=True)
    serve = sub.add_parser("serve")
    serve.add_argument("--state-dir", type=Path, required=True)
    serve.add_argument("--bind", required=True)
    export = sub.add_parser("export")
    export.add_argument("--state-dir", type=Path, required=True)
    export.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "init":
        fixture = WebFixture.create(args.state_dir, args.origin, args.condition, args.target_id, args.expected_target_ip)
        print(json.dumps({"run_id": fixture.config["run_id"], "page_url": fixture.page_url}))
    elif args.command == "export":
        fixture = WebFixture(args.state_dir)
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump({"run_id": fixture.config["run_id"], "records": fixture.rows()}, stream, indent=2)
    else:
        fixture = WebFixture(args.state_dir)
        address = ipaddress.ip_address(args.bind)
        if not address.is_private or address.is_unspecified or address.is_multicast or address.version != 4:
            raise ValueError("Bind requires a specific private/loopback IPv4 interface, never 0.0.0.0.")
        origin = urlsplit(fixture.config["origin"])
        if origin.hostname != str(address):
            raise ValueError("Bind address must match fixture origin IP.")
        server = ThreadingHTTPServer((args.bind, origin.port or 80), handler_for(fixture))
        server.serve_forever()


if __name__ == "__main__":
    main()
