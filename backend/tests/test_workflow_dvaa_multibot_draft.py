"""Offline checks for the non-operational, source-reviewed DVAA catalog draft."""
import json
import socket
from pathlib import Path

import pytest

from workflow.catalog import TargetCatalog, load_catalog
from workflow.models import CatalogConfig, TargetDraft


ROOT = Path(__file__).resolve().parents[2]
DRAFT = ROOT / "configs/workflow/authorized-targets.dvaa-multibot.draft.json"
EXAMPLE = ROOT / "configs/workflow/authorized-targets.example.json"
AGENTS = {
    "securebot": 7001, "helperbot": 7002, "legacybot": 7003,
    "codebot": 7004, "ragbot": 7005, "multimodal": 7006,
    "memorybot": 7007, "longwindbot": 7008, "ragbot-aim": 7014,
    "researchbot": 7015, "researchbot-aim": 7016,
    "flightbot": 7017, "flightbot-aim": 7018,
    "repobot": 7022, "repobot-aim": 7023,
}


@pytest.fixture(autouse=True)
def forbid_network_and_execution(monkeypatch):
    from tools.http import HttpClient
    from testing.executor import Executor
    from integrations.external_evaluator.pi import PiEvaluatorProvider

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Offline catalog test attempted network or execution")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(HttpClient, "request", forbidden)
    monkeypatch.setattr(Executor, "execute", forbidden)
    monkeypatch.setattr(PiEvaluatorProvider, "evaluate", forbidden)


def test_draft_profiles_match_source_reviewed_api_ids_ports_and_mapping():
    catalog = load_catalog(DRAFT)
    profiles = catalog.public_targets()
    assert len(profiles) == len(AGENTS)
    assert len({p["id"] for p in profiles}) == len(profiles)
    assert len({p["profile_revision"] for p in profiles}) == len(profiles)
    for p in profiles:
        agent_id = p["default_model"]
        assert agent_id in AGENTS
        assert p["models"] == [agent_id]
        assert p["endpoint"] == f"http://127.0.0.1:{AGENTS[agent_id]}/v1/chat/completions"
        assert p["platform_id"] == "dvaa" and p["platform_name"] == "DVAA"
        assert p["authorization_status"] == "review_required"
        assert p["protocol"] == "openai-chat"
        assert p["method"] == "POST"
        assert p["request_mapping"] == "openai-chat-user-message-v1"
        assert p["response_parser"] == "choices.0.message.content"
        assert p["credential_alias"] is None
        assert p["connection_probe"]["status"] == "unsupported"
        assert not p["connection_probe"]["security_execution_authorized"]
        draft = TargetDraft.model_validate({
            "target_id": p["id"], "profile_revision": p["profile_revision"],
            "policy_ref": p["policy_ref"], "endpoint": p["endpoint"],
            "protocol": p["protocol"], "method": p["method"],
            "model": agent_id, "request_mapping": p["request_mapping"],
            "response_parser": p["response_parser"],
            "timeout_seconds": p["timeout_default"], "credential_alias": None,
        })
        assert catalog.validate(draft) == ["operator_review_required"]


def test_legacy_researchbot_profile_unchanged():
    old = load_catalog(EXAMPLE).public_targets()[0]
    new = next(p for p in load_catalog(DRAFT).public_targets() if p["id"] == old["id"])
    for key in ("id", "name", "platform_id", "platform_name", "endpoint", "models", "default_model",
                "timeout_min", "timeout_max", "timeout_default", "protocol", "credential_alias"):
        assert new[key] == old[key]
    assert new["profile_revision"] == old["profile_revision"]


def test_duplicate_ids_and_unsupported_protocol_fail_closed():
    raw = json.loads(DRAFT.read_text(encoding="utf-8"))
    raw["targets"].append(dict(raw["targets"][0]))
    with pytest.raises(ValueError, match="Duplicate target identity"):
        CatalogConfig.model_validate(raw)
    raw["targets"].pop()
    raw["targets"][0]["protocol"] = "mcp"
    with pytest.raises(ValueError):
        CatalogConfig.model_validate(raw)
