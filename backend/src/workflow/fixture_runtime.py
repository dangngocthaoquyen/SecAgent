"""Loopback-only web fixture lifecycle for synthetic workflow integration tests.

Production GH-WEB-001 remains disabled until an isolated DVAA-to-fixture
network and collector-visible peer contract are operator reviewed.
"""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

from testing.web_fixture import WebFixture, handler_for


class LocalMockFixtureRuntime:
    """Own one fresh local HTTP page/collector; never bind a public interface."""

    provenance = "synthetic_mock"

    @contextmanager
    def open(self, run_dir: Path, target_id: str, *, condition: str = "attack"):
        if condition not in {"control", "attack"}:
            raise ValueError("Unsupported fixture condition.")
        server = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
        server.daemon_threads = True
        started = False
        thread = None
        try:
            origin = f"http://127.0.0.1:{server.server_address[1]}"
            fixture = WebFixture.create(run_dir / "fixture", origin, condition, target_id,
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
