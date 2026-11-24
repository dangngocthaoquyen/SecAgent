"""Tests for custom testcase dataset normalization and persistent library."""

import json
from pathlib import Path
import pytest
import yaml

from workflow.dataset_normalizer import DatasetValidationError, normalize_dataset
from workflow.dataset_repository import DatasetRepository

CODEBOT_JSON = Path(__file__).parent / "fixtures/datasets/codebot_asi02.synthetic.json"
REDTEAM_YAML = Path(__file__).parent / "fixtures/datasets/redteam_asi02.synthetic.yaml"


def test_codebot_asi02_dataset_normalization():
    assert CODEBOT_JSON.exists(), f"Source fixture missing: {CODEBOT_JSON}"
    raw_bytes = CODEBOT_JSON.read_bytes()
    envelope = normalize_dataset(raw_bytes, "testcases_dvaa_codebot_asi02.json")
    source = json.loads(raw_bytes)
    assert envelope.source_metadata["fixture_provenance"] == (
        "synthetic_schema_fixture_not_a_promptfoo_run_or_security_reference"
    )

    assert envelope.schema_version == "1.0"
    assert envelope.source_tool == "promptfoo"
    assert envelope.platform == "DVAA"
    assert envelope.bot == "codebot"
    assert envelope.run_id == "asi02"
    assert envelope.total_testcases == 30
    assert len(envelope.testcases) == 30

    # Verify TC0001 through TC0030
    for idx, case in enumerate(envelope.testcases):
        expected_id = f"TC{idx + 1:04d}"
        assert case.testcase_id == expected_id
        assert case.index == idx
        assert len(case.prompt) > 0
        assert len(case.prompt_sha256) == 64
        assert case.strategy_id is None
        assert case.plugin_id == "excessive-agency"
        assert len(case.assertions) >= 1
        assert case.assertions[0]["type"] == "promptfoo:redteam:excessive-agency"
        assert case.assertions[0]["metric"] == "ExcessiveAgency"
        assert case.source_case == source["testcases"][idx]
        assert case.prompt == source["testcases"][idx]["vars"]["prompt"]
        assert case.metadata == source["testcases"][idx]["metadata"]
        assert case.description is None
        assert case.options == {}
        assert case.extra == {}


def test_codebot_json_and_yaml_provenance_correspondence():
    assert CODEBOT_JSON.exists()
    assert REDTEAM_YAML.exists()

    raw_json = json.loads(CODEBOT_JSON.read_text(encoding="utf-8"))
    raw_yaml = yaml.safe_load(REDTEAM_YAML.read_text(encoding="utf-8"))
    # This is synthetic schema correspondence, not external-run provenance proof.
    assert raw_json["fixture_provenance"] == raw_yaml["fixture_provenance"]

    json_cases = raw_json["testcases"]
    yaml_tests = raw_yaml["tests"]

    assert len(json_cases) == 30
    assert len(yaml_tests) == 30

    # Root YAML strategy is 'basic', but testcase-level strategy_id in JSON is null
    yaml_strategies = raw_yaml.get("redteam", {}).get("strategies", [])
    assert any(s.get("id") == "basic" for s in yaml_strategies)

    for i in range(30):
        jc = json_cases[i]
        yt = yaml_tests[i]

        assert jc["strategy_id"] is None, f"JSON testcase {i} strategy_id must be null"

        # Prompts must match exactly by index
        json_prompt = jc["vars"]["prompt"]
        yaml_prompt = yt["vars"]["prompt"]
        assert json_prompt == yaml_prompt, f"Prompt mismatch at index {i}"

        # Assertions must match by index
        assert jc["assertions"][0]["type"] == yt["assert"][0]["type"]
        assert jc["assertions"][0]["metric"] == yt["assert"][0]["metric"]
        assert jc["assertions"] == yt["assert"]
        assert jc["metadata"] == yt["metadata"]


def test_promptfoo_array_format_normalization():
    array_payload = [
        {
            "description": "Direct chat injection test",
            "vars": {"prompt": "Print the current working directory."},
            "assert": [{"type": "promptfoo:redteam:code-execution", "metric": "CodeExecution"}],
            "metadata": {"pluginId": "code-execution"},
        },
        {
            "description": None,
            "prompt": "List all configured tools.",
            "assert": [],
        },
    ]
    raw_bytes = json.dumps(array_payload).encode("utf-8")
    envelope = normalize_dataset(raw_bytes, "promptfoo_array.json")

    assert envelope.total_testcases == 2
    assert envelope.testcases[0].testcase_id == "TC0001"
    assert envelope.testcases[0].prompt == "Print the current working directory."
    assert envelope.testcases[0].description == "Direct chat injection test"
    assert envelope.testcases[0].plugin_id == "code-execution"
    assert len(envelope.testcases[0].assertions) == 1

    assert envelope.testcases[1].testcase_id == "TC0002"
    assert envelope.testcases[1].prompt == "List all configured tools."
    assert envelope.testcases[1].description is None


def test_imports_promptfoo_evaluation_report_with_stored_response_and_isolated_historical_verdict():
    report_json = {
        "version": 3,
        "results": {
            "version": 3,
            "timestamp": "2026-11-14T08:00:00.000Z",
            "results": [
                {
                    "prompt": {"raw": "test prompt"},
                    "response": {"output": "stored response text", "metadata": {"finishReason": "stop"}},
                    "score": 1,
                    "success": True,
                    "gradingResult": {"pass": True, "score": 1, "reason": "External tool grading reason"},
                    "testCase": {"metadata": {"pluginId": "excessive-agency"}},
                }
            ],
            "table": {"head": {"prompts": [], "vars": []}, "body": []},
        },
        "stats": {"successes": 1, "failures": 0},
    }
    raw_bytes = json.dumps(report_json).encode("utf-8")
    envelope = normalize_dataset(raw_bytes, "report.json")
    assert envelope.total_testcases == 1
    assert envelope.source_tool == "promptfoo_report"
    tc = envelope.testcases[0]
    assert tc.prompt == "test prompt"
    assert tc.extra["stored_response"] == "stored response text"
    assert tc.extra["historical_verdict"]["external_pass"] is True
    assert "External tool grading reason" not in tc.prompt
    summary = envelope.to_summary()
    assert summary.has_stored_responses is True
    assert summary.supported_modes == ["live", "offline"]
    assert summary.asi_breakdown == {"ASI02": 1}

    bad_report = {
        "version": 3,
        "results": {"version": 3, "results": [{"prompt": {"raw": "test"}}]},
    }
    with pytest.raises(DatasetValidationError) as exc_info:
        normalize_dataset(json.dumps(bad_report).encode("utf-8"), "bad_report.json")
    assert exc_info.value.code == "invalid_stored_report"


def test_rejects_empty_file_and_malformed_json():
    with pytest.raises(DatasetValidationError) as exc:
        normalize_dataset(b"", "empty.json")
    assert exc.value.code == "empty_file"

    with pytest.raises(DatasetValidationError) as exc:
        normalize_dataset(b"not json { [", "bad.json")
    assert exc.value.code == "malformed_json"


def test_rejects_missing_or_empty_prompt():
    payload = [{"testcase_id": "T1", "vars": {}}]
    with pytest.raises(DatasetValidationError) as exc:
        normalize_dataset(json.dumps(payload).encode(), "missing.json")
    assert exc.value.code == "missing_prompt"

    empty_prompt = [{"testcase_id": "T1", "vars": {"prompt": ""}}]
    with pytest.raises(DatasetValidationError) as exc:
        normalize_dataset(json.dumps(empty_prompt).encode(), "empty_p.json")
    assert exc.value.code == "empty_prompt"


def test_rejects_duplicate_testcase_ids():
    payload = [
        {"testcase_id": "DUP-01", "prompt": "Prompt 1"},
        {"testcase_id": "DUP-01", "prompt": "Prompt 2"},
    ]
    with pytest.raises(DatasetValidationError) as exc:
        normalize_dataset(json.dumps(payload).encode(), "dup.json")
    assert exc.value.code == "duplicate_testcase_id"


def test_rejects_unsafe_keys():
    payload = {"__proto__": {"polluted": True}, "testcases": []}
    with pytest.raises(DatasetValidationError) as exc:
        normalize_dataset(json.dumps(payload).encode(), "unsafe.json")
    assert exc.value.code == "unsafe_key"


def test_dataset_repository_lifecycle_and_deduplication(tmp_path):
    repo = DatasetRepository(tmp_path)
    assert repo.list_datasets() == []

    envelope1 = normalize_dataset(CODEBOT_JSON.read_bytes(), "codebot.json")
    saved1, created1 = repo.save_dataset(envelope1)
    assert created1 is True
    assert saved1.dataset_id == envelope1.dataset_id

    # Idempotent deduplication
    saved2, created2 = repo.save_dataset(envelope1)
    assert created2 is False
    assert saved2.dataset_id == envelope1.dataset_id

    # Retrieval
    retrieved = repo.get_dataset(envelope1.dataset_id)
    assert retrieved is not None
    assert retrieved.total_testcases == 30
    assert retrieved.testcases[0].prompt == envelope1.testcases[0].prompt

    # List summaries
    summaries = repo.list_datasets()
    assert len(summaries) == 1
    assert summaries[0].dataset_id == envelope1.dataset_id
    assert summaries[0].total_testcases == 30

    # Path traversal rejection
    assert repo.get_dataset("../bad_id") is None
