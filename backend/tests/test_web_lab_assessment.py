"""Offline two-fixture lifecycle; the Docker boundary has its own opt-in test."""
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
import json
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from backend.scripts.serve_asi01_web_lab import handler_for
from workflow.web_lab_assessment import WebLabAssessment


def request(url, method="GET"):
    try:
        with urlopen(Request(url, method=method), timeout=3) as response:
            return response.status
    except HTTPError as error:
        return error.code


def test_two_fresh_fixtures_and_separate_windows(tmp_path):
    server = ThreadingHTTPServer(("127.0.0.1", 0), None)
    origin = f"http://127.0.0.1:{server.server_address[1]}"
    assessment = WebLabAssessment.create(tmp_path, origin, "dvaa-researchbot-lab", "127.0.0.1")
    server.RequestHandlerClass = handler_for(assessment)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        started = datetime.now(timezone.utc)
        assert request(assessment.attack.page_url) == 404
        assert request(origin + assessment.attack.callback_path) == 404
        assert request(assessment.preflight.page_url) == 200
        assert request(assessment.preflight.page_url, "POST") == 405
        result = assessment.verify_preflight(started, datetime.now(timezone.utc),
            target_request_count=1, target_execution_success=True)
        assert result["status"] == "verified" and result["security_verdict"] is None
        assert assessment.preflight_verified()
        assert request(assessment.preflight.page_url) == 404
        attack_started = datetime.now(timezone.utc)
        assert request(assessment.attack.page_url) == 200
        assert request(origin + assessment.attack.callback_path) == 200
        observed = assessment.record_attack_observation(
            attack_started, datetime.now(timezone.utc), target_request_count=1)
        assert observed["security_verdict"] is None
        assert observed["evidence"]["data"]["correlation_valid"] is True
        assert result["preflight_run_id"] != observed["attack_run_id"]
        assert assessment.identity["preflight_page_sha256"] != assessment.identity["attack_page_sha256"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_missing_fetch_wrong_peer_and_replay_do_not_verify(tmp_path):
    assessment = WebLabAssessment.create(tmp_path, "http://127.0.0.1:8787",
        "dvaa-researchbot-lab", "127.0.0.1")
    started = datetime.now(timezone.utc)
    assessment.preflight.record("page", "GET", "127.0.0.2")
    result = assessment.verify_preflight(started, datetime.now(timezone.utc),
        target_request_count=1, target_execution_success=True)
    assert result["status"] == "unverified" and result["security_verdict"] is None
    assert not assessment.preflight_verified()
    with pytest.raises(ValueError, match="verified preflight"):
        assessment.record_attack_observation(started, datetime.now(timezone.utc),
                                             target_request_count=1)
    new = WebLabAssessment.create(tmp_path, "http://127.0.0.1:8787",
        "dvaa-researchbot-lab", "127.0.0.1")
    assessment.attack.record("page", "GET", "127.0.0.1")
    assessment.attack.record("receipt", "GET", "127.0.0.1")
    (new.attack.directory / "events.jsonl").write_bytes(
        (assessment.attack.directory / "events.jsonl").read_bytes())
    evidence = new.attack.evidence(new.attack.created_at, datetime.now(timezone.utc))
    assert evidence["data"]["correlation_valid"] is False


def test_budget_window_and_manifest_tampering_fail_closed(tmp_path):
    assessment = WebLabAssessment.create(tmp_path, "http://127.0.0.1:8787",
        "dvaa-researchbot-lab", "127.0.0.1")
    started = datetime.now(timezone.utc)
    with pytest.raises(ValueError, match="one accounted"):
        assessment.verify_preflight(started, started, target_request_count=0,
                                    target_execution_success=True)
    with pytest.raises(ValueError, match="120 seconds"):
        assessment.verify_preflight(started, started + timedelta(seconds=121),
                                     target_request_count=1, target_execution_success=True)
    manifest = assessment.attack.directory / "manifest.json"
    content = json.loads(manifest.read_text())
    content["run_id"] = "f" * 32
    manifest.write_text(json.dumps(content))
    with pytest.raises(ValueError, match="identity or fixture hashes"):
        WebLabAssessment(assessment.directory)
