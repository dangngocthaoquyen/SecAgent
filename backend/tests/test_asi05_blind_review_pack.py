"""Offline integrity and blinding checks for the real ASI05 reviewer pack."""

from __future__ import annotations

import csv
from hashlib import sha256
import importlib.util
import io
import json
from pathlib import Path
import random
import socket
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "build_asi05_blind_review_pack", ROOT / "backend/scripts/build_asi05_blind_review_pack.py"
)
assert SPEC and SPEC.loader
pack = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pack)


@pytest.fixture(autouse=True)
def forbid_process_and_network(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Blind pack must not start a process or make a network request")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)


@pytest.fixture
def real_sources():
    source_root = ROOT / "results/local-controlled-runs"
    data = Path.home() / "AppData/Local/SecAgent"
    downloads = Path.home() / "Downloads"
    dataset = data / "targets/datasets" / f"{pack.DATASET_ID}.json"
    batches_present = all(
        (source_root / "batch-runs" / batch_id / "state.json").is_file()
        for batch_id in (pack.BATCH_1, pack.BATCH_2)
    )
    if not (source_root.exists() and dataset.exists() and downloads.exists() and batches_present):
        pytest.skip("Local historical ASI05 sources are unavailable")
    return source_root, data, downloads


@pytest.fixture
def built_pack(tmp_path, real_sources):
    source_root, data, downloads = real_sources
    class Args:
        pass
    args = Args()
    args.source_root = source_root
    args.local_data_dir = data
    args.downloads_dir = downloads
    args.reviewer_output_dir = tmp_path / "reviewers"
    args.mapping_output_dir = tmp_path / "restricted_mapping"
    numbers = iter(range(1, 17))
    summary = pack.build(
        args,
        review_id_factory=lambda: f"R-{next(numbers):016X}",
        rng=random.Random(17),
    )
    return args, summary


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_two_blind_reviewers_and_conditional_separation(built_pack):
    args, summary = built_pack
    assert summary == {
        "main_count": 14,
        "conditional_count": 2,
        "reviewer_packets": 2,
        "target_request_count": 0,
        "external_judge_attempts": 0,
        "stored_responses_are_raw_http": False,
    }
    r1 = args.reviewer_output_dir / "reviewer_1"
    r2 = args.reviewer_output_dir / "reviewer_2"
    for name in ("main_cases.jsonl", "conditional_cases.jsonl"):
        assert (r1 / name).read_bytes() == (r2 / name).read_bytes()
    main = read_jsonl(r1 / "main_cases.jsonl")
    conditional = read_jsonl(r1 / "conditional_cases.jsonl")
    assert len(main) == 14 and len(conditional) == 2
    assert all(row["redaction_status"] == "no_visible_marker" for row in main)
    assert all(row["redaction_status"] == "visible_marker_in_stored_response" for row in conditional)
    assert not (r1 / "source_mapping.json").exists()
    assert not (r2 / "source_mapping.json").exists()
    assert (args.mapping_output_dir / "source_mapping.json").exists()


def test_source_hash_prompt_response_and_provenance(built_pack, real_sources):
    args, _ = built_pack
    source_root, data, _ = real_sources
    _, prompts = pack.load_dataset(data / "targets/datasets" / f"{pack.DATASET_ID}.json")
    mapping = json.loads((args.mapping_output_dir / "source_mapping.json").read_text(encoding="utf-8"))
    records = read_jsonl(args.reviewer_output_dir / "reviewer_1/main_cases.jsonl")
    records += read_jsonl(args.reviewer_output_dir / "reviewer_1/conditional_cases.jsonl")
    by_id = {row["review_id"]: row for row in records}
    assert len(by_id) == len(mapping["records"]) == 16
    assert {(row["batch_id"], row["testcase_id"]) for row in mapping["records"]} == (
        set(pack.MAIN_CASES) | set(pack.CONDITIONAL_CASES)
    )
    for source in mapping["records"]:
        row = by_id[source["review_id"]]
        case = prompts[source["testcase_id"]]
        report_path = Path(source["source_report_path"])
        assert report_path.is_relative_to(source_root)
        report_bytes = report_path.read_bytes()
        report = json.loads(report_bytes)
        response = report["evaluation"]["observation"]["response_text"]
        assert sha256(report_bytes).hexdigest() == row["source_report_sha256"] == source["source_report_sha256"]
        assert row["attacker_input"] == case["prompt"]
        assert sha256(row["attacker_input"].encode()).hexdigest() == row["prompt_sha256"] == case["prompt_sha256"]
        assert row["stored_target_response"] == response
        assert sha256(response.encode()).hexdigest() == row["response_sha256"] == source["response_sha256"]
        assert row["response_completeness"] == {
            "reported_complete": report["evaluation"]["observation"]["response_complete"],
            "independently_reverified_from_raw_http": False,
        }
        assert row["evidence_provenance"]["source"] == report["source_provenance"]
        assert row["evidence_provenance"]["target_request_count"] == report["runtime_snapshot"]["target_request_count"]
        assert row["evidence_provenance"]["independent_runtime_execution_verified"] is False
        assert row["additional_redaction_applied"] is False


def test_no_historical_judge_fields_or_reference_labels(built_pack):
    args, _ = built_pack
    allowed = {
        "review_id", "attacker_input", "prompt_sha256", "stored_target_response",
        "response_sha256", "source_report_sha256", "response_completeness",
        "redaction_status", "additional_redaction_applied", "policy_revision_sha256",
        "policy_clauses", "evidence_provenance", "provenance_limitations",
        *pack.ADJUDICATION_FIELDS,
    }
    mapping = json.loads((args.mapping_output_dir / "source_mapping.json").read_text(encoding="utf-8"))
    source_ids = {value for source in mapping["records"] for value in (
        source["batch_id"], source["testcase_id"], source["run_id"]
    )}
    for slot in ("reviewer_1", "reviewer_2"):
        directory = args.reviewer_output_dir / slot
        for cohort in ("main", "conditional"):
            rows = read_jsonl(directory / f"{cohort}_cases.jsonl")
            for row in rows:
                assert set(row) == allowed
                assert all(row[field] is None for field in pack.ADJUDICATION_FIELDS if field != "review_id")
            with (directory / f"{cohort}_labels.csv").open(encoding="utf-8-sig", newline="") as stream:
                labels = list(csv.DictReader(stream))
            assert len(labels) == len(rows)
            assert {item["review_id"] for item in labels} == {item["review_id"] for item in rows}
            assert all(not value for item in labels for field, value in item.items() if field != "review_id")
        packet_bytes = b"".join(path.read_bytes() for path in directory.iterdir() if path.is_file())
        assert all(identifier.encode() not in packet_bytes for identifier in source_ids)
        assert b'"historical_verdict"' not in packet_bytes
        assert b'"judge_recommendation"' not in packet_bytes
        assert b'"reference_label"' not in packet_bytes
    assert all("verdict" not in row and "judge" not in row for row in mapping["records"])


def test_packet_manifest_hashes(built_pack):
    args, _ = built_pack
    for slot in ("reviewer_1", "reviewer_2"):
        directory = args.reviewer_output_dir / slot
        manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["blind_packet"] is True
        for name, expected in manifest["files"].items():
            assert sha256((directory / name).read_bytes()).hexdigest() == expected


def test_mismatched_hash_is_rejected():
    with pytest.raises(pack.PackError, match="Source report SHA256 mismatch"):
        pack.verify_digest(b"tampered", "0" * 64, "Source report")


def test_secret_gate_does_not_echo_secret():
    sentinel = "sk-" + "SENTINELVALUE" * 2
    assert pack.safe_for_review(sentinel) is False
    assert pack.safe_for_review("https://example.invalid/path") is True
    assert pack.safe_for_review("https://internal.example/path") is False
