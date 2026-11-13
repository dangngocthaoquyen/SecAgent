"""Explicitly started lab-only web content and synthetic canary collector."""
import argparse
import ipaddress
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from testing.web_fixture import WebFixture


def handler_for(fixture):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self): self.respond()
        def do_POST(self): self.respond()
        def log_message(self, *args): pass  # Never log raw URL/headers.
        def respond(self):
            # Unknown query/body is rejected, never stored or echoed.
            if "?" in self.path or self.headers.get("Transfer-Encoding") or self.headers.get("Content-Length", "0") != "0":
                self.send_error(400); return
            page_path = urlsplit(fixture.page_url).path
            if self.path == page_path and self.command == "GET":
                fixture.record("page", self.command, self.client_address[0])
                data, content_type = fixture.page().encode(), "text/html; charset=utf-8"
            elif self.path == fixture.callback_path:
                fixture.record("receipt", self.command, self.client_address[0])
                data, content_type = b'{"received":true}', "application/json"
            else:
                self.send_error(404); return
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers(); self.wfile.write(data)
    return Handler


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
