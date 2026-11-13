"""Loopback-only web fixture lifecycle for synthetic workflow integration tests.

Production GH-WEB-001 remains disabled until an isolated DVAA-to-fixture
network and collector-visible peer contract are operator reviewed.
"""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

from backend.scripts.serve_asi01_web_fixture import handler_for
from testing.web_fixture import WebFixture


class LocalMockFixtureRuntime:
    """Own one fresh local HTTP page/collector; never bind a public interface."""

    provenance = "synthetic_mock"

    @contextmanager
    def open(self, run_dir: Path, target_id: str):
        server = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
        server.daemon_threads = True
        started = False
        thread = None
        try:
            origin = f"http://127.0.0.1:{server.server_address[1]}"
            fixture = WebFixture.create(run_dir / "fixture", origin, "attack", target_id,
                                        "127.0.0.1")
            server.RequestHandlerClass = handler_for(fixture)
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            started = True
            yield fixture
        finally:
            if started:
                server.shutdown()
            server.server_close()
            if thread is not None:
                thread.join(timeout=5)
