"""The ASI03 live pilot must fail before target dispatch without explicit Pi authority."""

import json
import socket
from types import SimpleNamespace

import pytest

from backend.scripts import pilot_asi03_dvaa_response as pilot


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr(socket.socket, "connect", lambda *_: pytest.fail("Network forbidden"))


def config_file(tmp_path, *, max_calls=1):
    executable = tmp_path / "pi.cmd"
    executable.write_text("test-only executable", encoding="utf-8")
    path = tmp_path / "judge.json"
    path.write_text(json.dumps({
        "mode": "hybrid", "judge_enabled": True, "allow_live_judge": True,
        "max_judge_calls": max_calls,
        "require_complete_response_for_semantic": True,
        "pi": {"executable": str(executable), "provider": "fake",
               "model": "fake-model", "timeout_seconds": 1,
               "credential_env": ["ASI03_TEST_CREDENTIAL"]},
    }), encoding="utf-8")
    return path


def test_default_pilot_keeps_judge_disabled_and_ignores_config(tmp_path):
    config, digest = pilot.evaluation_config(
        allow_live_judge=False, judge_config=tmp_path / "missing.json")
    assert config.mode == "hybrid"
    assert not config.judge_enabled and not config.allow_live_judge
    assert config.max_judge_calls == 0 and digest is None


def test_missing_credential_blocks_before_target_setup(tmp_path, monkeypatch):
    path = config_file(tmp_path)
    monkeypatch.delenv("ASI03_TEST_CREDENTIAL", raising=False)
    monkeypatch.setattr(pilot, "ManagedTargetCatalog",
                        lambda *_args, **_kwargs: pytest.fail("Target setup reached"))
    with pytest.raises(ValueError, match="credential is unavailable"):
        pilot.main(["--allow-live-judge", "--judge-config", str(path)])


def test_explicit_optin_uses_one_call_budget_without_exposing_secret(tmp_path, monkeypatch):
    path = config_file(tmp_path)
    sentinel = "ASI03-SECRET-SENTINEL-DO-NOT-PRINT"
    monkeypatch.setenv("ASI03_TEST_CREDENTIAL", sentinel)
    config, digest = pilot.evaluation_config(
        allow_live_judge=True, judge_config=path)
    assert config.judge_enabled and config.allow_live_judge
    assert config.max_judge_calls == 1 and config.require_complete_response_for_semantic
    assert len(digest) == 64
    assert sentinel not in repr(config) and sentinel not in digest


def test_multi_attempt_config_is_rejected(tmp_path, monkeypatch):
    path = config_file(tmp_path, max_calls=2)
    monkeypatch.setenv("ASI03_TEST_CREDENTIAL", "synthetic-only")
    with pytest.raises(ValueError, match="one bounded Hybrid Pi attempt"):
        pilot.evaluation_config(allow_live_judge=True, judge_config=path)


def test_pinned_policy_dataset_prompt_and_target_revision():
    policy = {"policy_id": pilot.POLICY_ID,
              "revision_sha256": pilot.POLICY_REVISION}
    dataset = SimpleNamespace(dataset_id=pilot.DATASET_ID,
        file_sha256=pilot.DATASET_SHA256, content_sha256=pilot.CONTENT_SHA256)
    source = SimpleNamespace(prompt_sha256=pilot.PROMPT_SHA256)
    pilot.verify_pinned_sources(policy, dataset, source, pilot.TARGET_REVISION)
    with pytest.raises(ValueError, match="revision changed"):
        pilot.verify_pinned_sources(policy, dataset, source, "0" * 64)
    with pytest.raises(ValueError, match="revision changed"):
        pilot.verify_pinned_sources({**policy, "revision_sha256": "0" * 64},
                                    dataset, source, pilot.TARGET_REVISION)
    with pytest.raises(ValueError, match="revision changed"):
        pilot.verify_pinned_sources(policy, dataset,
            SimpleNamespace(prompt_sha256="0" * 64), pilot.TARGET_REVISION)
