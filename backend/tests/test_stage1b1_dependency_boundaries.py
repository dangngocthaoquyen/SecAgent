"""Behavioral and import-boundary regression tests for Stage 1B.1."""

import ast
import io
import json
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlsplit

import pytest

from backend.scripts import prepare_asi01_web_lab, serve_asi01_web_fixture
from testing.web_fixture import FACTS, WebFixture, handler_for
from workflow import fixture_runtime, web_lab_runtime


ROOT = Path(__file__).resolve().parents[2]


def _backend_src_script_imports() -> list[tuple[str, int, str]]:
    hits: list[tuple[str, int, str]] = []
    for path in sorted((ROOT / "backend" / "src").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if "script" in alias.name:
                        hits.append((str(path.relative_to(ROOT)), node.lineno, alias.name))
            elif isinstance(node, ast.ImportFrom) and node.module and "script" in node.module:
                hits.append((str(path.relative_to(ROOT)), node.lineno, node.module))
    return hits


def test_zero_production_to_script_imports_remain():
    assert _backend_src_script_imports() == []


def test_fixture_handler_for_serves_page_and_records_sanitized_receipt(tmp_path):
    fixture = WebFixture.create(tmp_path / "fixture", "http://127.0.0.1:8787", "attack", "dvaa-researchbot", "127.0.0.1")
    assert serve_asi01_web_fixture.handler_for is handler_for

    handler_cls = handler_for(fixture)

    def invoke(command: str, path: str, headers: dict[str, str] | None = None):
        handler = handler_cls.__new__(handler_cls)
        handler.client_address = ("127.0.0.1", 5555)
        handler.command = command
        handler.path = path
        handler.headers = headers or {}
        handler.wfile = io.BytesIO()
        statuses: list[int] = []
        sent_headers: list[tuple[str, str]] = []
        handler.send_response = statuses.append
        handler.send_header = lambda k, v: sent_headers.append((k, v))
        handler.end_headers = lambda: None
        handler.send_error = statuses.append
        handler.respond()
        return statuses[-1], dict(sent_headers), handler.wfile.getvalue()

    page_status, page_headers, page_body = invoke("GET", urlsplit(fixture.page_url).path)
    assert page_status == 200
    assert page_headers["Content-Type"] == "text/html; charset=utf-8"
    assert page_headers["Cache-Control"] == "no-store"
    assert FACTS.encode() in page_body

    cb_status, cb_headers, cb_body = invoke("GET", fixture.callback_path, {"Authorization": "SECRET_HEADER"})
    assert cb_status == 200
    assert cb_headers["Content-Type"] == "application/json"
    assert cb_body == b'{"received":true}'

    bad_status, _, _ = invoke("GET", fixture.callback_path + "?q=1")
    assert bad_status == 400
    miss_status, _, _ = invoke("GET", "/unknown")
    assert miss_status == 404

    rows = fixture.rows()
    assert [r["kind"] for r in rows] == ["page", "receipt"]
    assert all(r["peer_matches"] is True for r in rows)
    assert fixture.config["canary"] not in (fixture.directory / "events.jsonl").read_text(encoding="utf-8")


def test_web_lab_runtime_initialize_and_script_cli_preserve_contracts(tmp_path, monkeypatch, capsys):
    assert prepare_asi01_web_lab.ORIGIN == web_lab_runtime.ORIGIN == "http://172.30.79.3:8787"
    assert prepare_asi01_web_lab.PEER == web_lab_runtime.PEER == "172.30.79.2"
    assert prepare_asi01_web_lab.TARGET == web_lab_runtime.TARGET == "dvaa-researchbot-web-lab"

    digest = "sha256:" + "a" * 64
    guard_digest = "nginx@sha256:" + "b" * 64

    def fake_output(*argv):
        if argv[:3] == ("docker", "network", "ls"):
            return ""
        if argv[:3] == ("docker", "image", "inspect"):
            return digest
        if argv[0] == "powershell":
            return "[]"
        raise AssertionError(f"Unexpected subprocess command: {argv}")

    monkeypatch.setattr(web_lab_runtime, "output", fake_output)

    with pytest.raises(ValueError, match="sha256 image ID"):
        web_lab_runtime.reviewed_image("latest")
    with pytest.raises(ValueError, match="repository@sha256 digest"):
        web_lab_runtime.reviewed_base("nginx:latest")
    with pytest.raises(ValueError, match="outside the repository"):
        web_lab_runtime.initialize(ROOT / "results", digest, digest, digest, guard_digest)

    prepare_asi01_web_lab.main([
        "--state-parent", str(tmp_path),
        "--dvaa-image", digest,
        "--fixture-image", digest,
        "--proxy-image", digest,
        "--guard-base-image", guard_digest,
    ])
    payload = json.loads(capsys.readouterr().out)
    assert payload["phase"] == "preflight"
    assert payload["live_dispatch_enabled"] is False

    assessment_dir = Path(payload["assessment_directory"])
    compose_env = (assessment_dir / "compose.env").read_text(encoding="utf-8")
    assert f"DVAA_IMAGE='{digest}'" in compose_env
    assert f"GUARD_BASE_IMAGE='{guard_digest}'" in compose_env
    assert f"WEB_LAB_STATE_DIR='{assessment_dir.as_posix()}'" in compose_env
    assert (assessment_dir / "assessment.json").is_file()


def test_clean_src_only_pythonpath_imports_all_workflows_without_scripts(tmp_path):
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "import testing.web_fixture, testing.report_builder, workflow.fixture_runtime, workflow.web_lab_runtime, workflow.dispatch, workflow.web_live_batch, workflow.web_mock_batch, workflow.api",
        ],
        cwd=tmp_path,
        env={"PYTHONPATH": str(ROOT / "backend" / "src")},
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
