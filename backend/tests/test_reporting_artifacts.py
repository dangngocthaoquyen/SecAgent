"""Synthetic immutable-archive checks; no dependency on local live results."""
import csv
import hashlib
import json
from pathlib import Path
import socket
import subprocess

import httpx
import pytest
from pydantic import ValidationError

from reporting import normalize_report_bytes
from reporting.artifacts import ArchiveVerificationError, MAX_ARTIFACT_BYTES, verify_archive
from reporting.models import ArchiveVerification
from reporting.verify import main

FIXTURES = Path(__file__).parent / "fixtures/reporting"
EXECUTION = "archive/reports/native.json"
ASSESSMENT = "assessment.json"
INVENTORY = "archive/evidence-sha256.csv"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write_json(path, row):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(row, ensure_ascii=False), encoding="utf-8")


def rehash(root):
    files = ["archive/fixture/manifest.json", "archive/fixture/events.jsonl",
             "archive/sanitized-collector-after.json", EXECUTION]
    with (root / INVENTORY).open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["Path", "Hash"])
        for name in files:
            writer.writerow([str(root / name), sha((root / name).read_bytes()).upper()])


@pytest.fixture(autouse=True)
def no_execution_or_network(monkeypatch):
    def blocked(*a, **k):
        raise AssertionError("Archive verification must not execute or connect")
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(httpx.Client, "request", blocked)
    monkeypatch.setattr(subprocess, "Popen", blocked)


@pytest.fixture
def archive(tmp_path):
    run, canary = "a" * 32, "b" * 32
    manifest = dict(schema=1, run_id=run, canary=canary, origin="http://fixture:8080",
                    condition="attack", target_id="synthetic-researchbot", expected_peer="172.20.0.2",
                    created_at="2026-11-07T00:00:00Z")
    write_json(tmp_path / "archive/fixture/manifest.json", manifest)
    events = [dict(schema=1, kind=kind, method="GET", run_id=run, collector_id="canary-" + run,
                   canary_sha256=sha(canary.encode()), peer_matches=True,
                   timestamp=f"2026-11-07T00:00:0{index}Z") for index, kind in enumerate(["page", "receipt"], 1)]
    (tmp_path / "archive/fixture/events.jsonl").write_text(
        "\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
    write_json(tmp_path / "archive/sanitized-collector-after.json", {"run_id": run, "records": events})
    native = json.loads((FIXTURES / "native-fail.json").read_text(encoding="utf-8"))
    e = native["evaluation"]
    e["timestamp"] = "2026-11-07T00:01:00Z"
    e["target_id"] = manifest["target_id"]
    e["observation"]["evidence"] = [dict(kind="collector_receipt", source="local_collector",
        name="canary-" + run, reference="collector." + run, success=True,
        data=dict(provenance="independent_local_collector", run_id=run, collector_id="canary-" + run,
                  condition="attack", correlation_valid=True, page_served=True, receipt_count=1,
                  observation_complete=False, manifest_sha256=sha((tmp_path / "archive/fixture/manifest.json").read_bytes()),
                  log_sha256=sha(json.dumps(events, sort_keys=True).encode()), observed_method="GET",
                  receipt_timestamp=events[1]["timestamp"]))]
    write_json(tmp_path / EXECUTION, native)
    cross = json.loads((FIXTURES / "archived-agreement.json").read_text(encoding="utf-8"))
    cross["original"].update(secagent_run_id=e["run_id"], fixture_correlation_id=run,
                             report_file_byte_sha256=sha((tmp_path / EXECUTION).read_bytes()))
    write_json(tmp_path / ASSESSMENT, cross)
    rehash(tmp_path)
    return tmp_path


def verify(root, **kwargs):
    return verify_archive(root, inventory=INVENTORY, execution=EXECUTION,
                          assessment=kwargs.pop("assessment", ASSESSMENT), **kwargs)


def test_valid_archive_dimensions_and_historical_verdicts_unchanged(archive):
    before = {p: p.read_bytes() for p in archive.rglob("*") if p.is_file()}
    result = verify(archive)
    v = result.verification
    assert v.file_integrity == v.internal_evidence_consistency == v.collector_canonical_digest == v.crosscheck_linkage == "verified"
    assert v.external_action_attestation == "not_performed"
    assert v.receipt_count == 1 and v.observed_methods == ["GET"]
    assert result.execution.security.verdict == "FAIL"
    assert result.assessment.judge.recommendation == "FAIL"
    assert result.assessment.comparison.state == "comparable_agreement"
    assert result.assessment.target_execution_performed is False
    assert result.execution.observation.response_completeness.state == "unknown"
    assert result.execution.source.archive_verification == "not_performed"
    assert result.execution.observation.evidence[0].verification.performed_by_normalizer is False
    assert all(p.read_bytes() == raw for p, raw in before.items())
    original = normalize_report_bytes(before[archive / EXECUTION]).model_dump()
    projected = result.execution.model_dump()
    projected["artifact_verification"] = None
    assert original == projected
    assert result.model_dump_json() == verify(archive).model_dump_json()


def test_file_hash_mismatch_and_missing_artifact_are_not_security_changes(archive):
    p = archive / "archive/fixture/events.jsonl"
    p.write_bytes(p.read_bytes() + b" ")
    result = verify(archive)
    assert result.verification.file_integrity == "mismatch"
    assert result.execution.security.verdict == "FAIL"
    p.unlink()
    result = verify(archive)
    assert result.verification.file_integrity == result.verification.internal_evidence_consistency == "missing"


@pytest.mark.parametrize("mutation", ["duplicate", "bad_hash", "header", "extra_column", "quoted", "external", "traversal"])
def test_bad_inventory_rejected(archive, mutation):
    p = archive / INVENTORY
    rows = list(csv.reader(p.read_text(encoding="utf-8").splitlines()))
    if mutation == "duplicate": rows[2] = rows[1]
    elif mutation == "bad_hash": rows[1][1] = "not-a-hash"
    elif mutation == "header": rows[0] = ["File", "SHA"]
    elif mutation == "extra_column": rows[1].append("extra")
    elif mutation == "external": rows[1][0] = str(archive.parent / "private.json")
    elif mutation == "traversal": rows[1][0] = "../private.json"
    if mutation == "quoted": p.write_text('Path,Hash\n"unterminated', encoding="utf-8")
    else:
        with p.open("w", encoding="utf-8", newline="") as stream: csv.writer(stream).writerows(rows)
    with pytest.raises(ArchiveVerificationError): verify(archive)


@pytest.mark.parametrize("key,value", [("report_file_byte_sha256", "c" * 64), ("secagent_run_id", "different-run")])
def test_parent_link_must_match_both_id_and_bytes(archive, key, value):
    p = archive / ASSESSMENT
    row = json.loads(p.read_text(encoding="utf-8"))
    row["original"][key] = value
    write_json(p, row)
    result = verify(archive)
    assert result.verification.crosscheck_linkage == "mismatch"
    assert result.execution.security.verdict == "FAIL"
    assert result.assessment.source_execution.original_verdict_snapshot == "FAIL"


@pytest.mark.parametrize("mutation,check", [("correlation", "correlation"), ("peer", "peer_match_recorded"),
    ("ordering", "event_ordering"), ("receipt", "callback_receipt"), ("export", "collector_export"),
    ("method", "receipt_claims"), ("canary", "correlation")])
def test_internal_record_conflicts_even_when_file_hashes_match(archive, mutation, check):
    p = archive / "archive/fixture/events.jsonl"
    events = [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines()]
    if mutation == "correlation": events[1]["run_id"] = "c" * 32
    elif mutation == "peer": events[1]["peer_matches"] = False
    elif mutation == "ordering": events.reverse()
    elif mutation == "receipt": events.pop()
    elif mutation == "method": events[1]["method"] = "POST"
    elif mutation == "canary": events[1]["canary_sha256"] = "d" * 64
    elif mutation == "export":
        write_json(archive / "archive/sanitized-collector-after.json", {"run_id": "wrong", "records": events})
    p.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
    rehash(archive)
    result = verify(archive)
    assert result.verification.file_integrity == "verified"
    assert result.verification.checks[check] in {"mismatch", "missing"}
    assert result.verification.internal_evidence_consistency != "verified"


def test_missing_inventory_or_parent_and_no_assessment(archive):
    result = verify(archive, assessment=None)
    assert result.verification.crosscheck_linkage == "not_performed"
    assert result.assessment is None
    (archive / INVENTORY).unlink()
    assert verify(archive).verification.file_integrity == "missing"
    (archive / EXECUTION).unlink()
    result = verify(archive)
    assert result.execution is None and result.verification.crosscheck_linkage == "missing"


@pytest.mark.parametrize("path", ["../private", "archive/../private", "https://example.com/report", "archive/file:stream"])
def test_unsafe_selection_rejected(archive, path):
    with pytest.raises(ArchiveVerificationError):
        verify_archive(archive, inventory=path, execution=EXECUTION)


def test_reparse_point_rejected_portably(archive, monkeypatch):
    import reporting.artifacts as module
    original = Path.lstat
    class Reparse:
        st_mode = 0
        st_file_attributes = 0x400
    def fake(path, *a, **k):
        return Reparse() if path == archive / "archive/fixture" else original(path, *a, **k)
    monkeypatch.setattr(module.Path, "lstat", fake)
    with pytest.raises(ArchiveVerificationError, match="reparse"):
        verify(archive)


def test_real_symlink_rejected_when_supported(archive):
    link = archive / "linked"
    try:
        link.symlink_to(archive / "archive", target_is_directory=True)
    except OSError:
        pytest.skip("OS does not permit symlink creation; reparse rejection tested separately")
    with pytest.raises(ArchiveVerificationError):
        verify_archive(archive, inventory="linked/evidence-sha256.csv", execution=EXECUTION)


def test_oversized_artifact_rejected_without_reading_contents(archive):
    p = archive / "archive/fixture/events.jsonl"
    with p.open("wb") as stream: stream.truncate(MAX_ARTIFACT_BYTES + 1)
    with pytest.raises(ArchiveVerificationError, match="size limit"): verify(archive)


def test_unknown_state_and_external_attestation_cannot_be_forged():
    with pytest.raises(ValidationError): ArchiveVerification(file_integrity="probably")
    with pytest.raises(ValidationError): ArchiveVerification(external_action_attestation="verified")


def test_no_raw_canaries_or_network_details_and_cli_is_read_only(archive, capsys):
    result = verify(archive)
    output = result.model_dump_json()
    for secret in ("a" * 32, "b" * 32, "http://fixture:8080", "172.20.0.2"):
        assert secret not in output
    assert main([str(archive), "--inventory", INVENTORY, "--execution", EXECUTION, "--assessment", ASSESSMENT]) == 0
    assert json.loads(capsys.readouterr().out)["verification"]["file_integrity"] == "verified"


def test_canonical_digest_is_not_jsonl_byte_digest(archive):
    result = verify(archive)
    events_check = next(a for a in result.verification.artifacts if a.artifact_role == "events")
    assert events_check.actual_file_byte_sha256 != result.verification.computed_collector_canonical_sha256


@pytest.mark.parametrize("file,content", [("archive/fixture/manifest.json", b'{"schema":1,"schema":1}'),
    ("archive/fixture/events.jsonl", b'{"timestamp":NaN}'), ("archive/fixture/manifest.json", b'\xff')])
def test_malformed_or_non_utf8_evidence_never_verified(archive, file, content):
    (archive / file).write_bytes(content)
    rehash(archive)
    result = verify(archive).verification
    assert result.internal_evidence_consistency != "verified"
    assert result.checks["evidence_format"] == "unsupported"


@pytest.mark.parametrize("field,value", [("receipt_count", 2), ("observed_method", "POST"),
    ("provenance", None), ("receipt_timestamp", "2025-01-01T00:00:00Z")])
def test_report_claims_are_checked_without_reassigning_verdict(archive, field, value):
    p = archive / EXECUTION
    row = json.loads(p.read_text(encoding="utf-8"))
    row["evaluation"]["observation"]["evidence"][0]["data"][field] = value
    write_json(p, row)
    rehash(archive)
    result = verify(archive)
    assert result.verification.file_integrity == "verified"
    assert result.verification.internal_evidence_consistency != "verified"
    assert result.execution.security.verdict == "FAIL"


def test_incorrect_fixture_link_is_separate_from_parent_id_and_hash(archive):
    p = archive / ASSESSMENT
    row = json.loads(p.read_text(encoding="utf-8"))
    row["original"]["fixture_correlation_id"] = "different-fixture"
    write_json(p, row)
    result = verify(archive)
    assert result.verification.crosscheck_linkage == "verified"
    assert result.verification.checks["crosscheck_fixture_correlation"] == "mismatch"
    assert main([str(archive), "--inventory", INVENTORY, "--execution", EXECUTION,
                 "--assessment", ASSESSMENT]) == 1


@pytest.mark.parametrize("schema", [2, True])
def test_unsupported_fixture_schema_does_not_claim_consistency(archive, schema):
    p = archive / "archive/fixture/manifest.json"
    row = json.loads(p.read_text(encoding="utf-8"))
    row["schema"] = schema
    write_json(p, row)
    rehash(archive)
    assert verify(archive).verification.internal_evidence_consistency == "unsupported"


def test_unrecognized_asi_profile_is_not_invented(archive):
    p = archive / EXECUTION
    row = json.loads(p.read_text(encoding="utf-8"))
    row["category"] = "tool_misuse"
    row["evaluation"]["testcase_id"] = row["testcase_id"] = "TM-SYNTHETIC"
    write_json(p, row)
    rehash(archive)
    assert verify(archive).verification.internal_evidence_consistency == "unsupported"


def test_known_canary_is_redacted_even_in_allowlisted_scalar_data(archive):
    p = archive / EXECUTION
    row = json.loads(p.read_text(encoding="utf-8"))
    row["evaluation"]["observation"]["evidence"][0]["data"]["condition"] = "b" * 32
    write_json(p, row)
    rehash(archive)
    assert "b" * 32 not in verify(archive).model_dump_json()


def test_unc_root_rejected_before_filesystem_access(monkeypatch):
    def blocked(*a, **k): raise AssertionError("UNC root must not be touched")
    monkeypatch.setattr(Path, "lstat", blocked)
    with pytest.raises(ArchiveVerificationError, match="Network"):
        verify_archive(r"\\untrusted\share", inventory="evidence-sha256.csv", execution="report.json")


def test_missing_assessment_and_default_normalization_stays_unverified(archive):
    (archive / ASSESSMENT).unlink()
    result = verify(archive)
    assert result.assessment is None
    assert result.verification.crosscheck_linkage == "missing"
    assert normalize_report_bytes((archive / EXECUTION).read_bytes()).artifact_verification is None


def test_cli_rejection_does_not_echo_raw_sensitive_paths(archive, capsys):
    assert main([str(archive), "--inventory", "../canary-private", "--execution", EXECUTION]) == 2
    captured = capsys.readouterr()
    assert "canary-private" not in captured.err and not captured.out


@pytest.mark.parametrize("key,value,check", [("final_verdict", "PASS", "crosscheck_verdict_snapshots"),
    ("target_id", "wrong-target", "crosscheck_identity_claims")])
def test_linked_assessment_snapshot_conflicts_are_explicit(archive, key, value, check):
    p = archive / ASSESSMENT
    row = json.loads(p.read_text(encoding="utf-8"))
    row["original"][key] = value
    write_json(p, row)
    result = verify(archive)
    assert result.verification.crosscheck_linkage == "verified"
    assert result.verification.checks[check] == "mismatch"
    assert result.execution.security.verdict == "FAIL"


def test_source_cannot_opt_itself_into_new_verification(archive):
    row = json.loads((archive / EXECUTION).read_text(encoding="utf-8"))
    row["artifact_verification"] = {"file_integrity": "verified", "external_action_attestation": "verified"}
    result = normalize_report_bytes(json.dumps(row).encode())
    assert result.artifact_verification is None


def test_missing_or_invalid_timestamp_does_not_become_ordering_proof(archive):
    p = archive / "archive/fixture/events.jsonl"
    events = [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines()]
    events[1]["timestamp"] = "2026-11-07T00:00:02"
    p.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
    rehash(archive)
    result = verify(archive).verification
    assert result.internal_evidence_consistency != "verified"
    assert result.checks["evidence_format"] == "unsupported"
