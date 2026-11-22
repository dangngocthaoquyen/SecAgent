"""Route only fresh Web Lab pages and the attack callback on a private IP."""
import argparse
import ipaddress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from workflow.web_lab_assessment import WebLabAssessment


def handler_for(assessment: WebLabAssessment):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # Never log paths, headers, IPs or canaries.

        def do_GET(self):
            self.respond()

        def do_POST(self):
            self.respond()

        def respond(self):
            if ("?" in self.path or self.headers.get("Transfer-Encoding")
                    or self.headers.get("Content-Length", "0") != "0"):
                self.send_error(400); return
            control = assessment.preflight
            attack = assessment.attack
            if self.command != "GET":
                self.send_error(405); return
            if self.path == urlsplit(control.page_url).path and assessment.phase == "preflight":
                fixture, kind = control, "page"
                data, content_type = control.page().encode(), "text/html; charset=utf-8"
            elif (self.path == urlsplit(attack.page_url).path
                    and assessment.preflight_verified()):
                fixture, kind = attack, "page"
                data, content_type = attack.page().encode(), "text/html; charset=utf-8"
            elif self.path == attack.callback_path and assessment.preflight_verified():
                fixture, kind = attack, "receipt"
                data, content_type = b'{"received":true}', "application/json"
            else:
                self.send_error(404); return
            fixture.record(kind, self.command, self.client_address[0])
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
    return Handler


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["serve"])
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--bind", required=True)
    args = parser.parse_args(argv)
    address = ipaddress.ip_address(args.bind)
    if (address.version != 4 or not address.is_private or address.is_unspecified
            or address.is_multicast):
        raise ValueError("Fixture must bind a specific private IPv4 address.")
    assessment = WebLabAssessment(args.state_dir)
    origin = urlsplit(assessment.preflight.config["origin"])
    if origin.hostname != str(address) or origin.port != 8787:
        raise ValueError("Bind address and port must match the reviewed fixture origin.")
    server = ThreadingHTTPServer((args.bind, origin.port), handler_for(assessment))
    server.serve_forever()


if __name__ == "__main__":
    main()
