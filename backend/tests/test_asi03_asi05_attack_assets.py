"""Schema, binding, and network-free pipeline tests for ASI03/ASI05 assets."""

from pathlib import Path
from typing import Any

import pytest

from core.models import (
    EvaluationStatus,
    ExecutionResult,
    TargetInterface,
    TargetProfile,
    TestInput as CoreTestInput,
)
from payloads import PayloadLoader, PayloadRenderer
from targets.adapters import BaseTargetAdapter
from testing import Executor, Runner, TestCaseLoader, bind_testcase_variables


ROOT = Path(__file__).resolve().parents[2]
GROUPS = {
    "identity_privilege_abuse": ("IPA", "IPA-P001", "IPA-PC01"),
    "unexpected_code_execution": ("UCE", "UCE-P001", "UCE-PC01"),
}


def load_case(group: str, case_id: str):
    return TestCaseLoader().load(ROOT / "testcases" / group / f"{case_id}.yaml")


def render_case(group: str, case_id: str, overrides: dict[str, Any] | None = None):
    case = bind_testcase_variables(load_case(group, case_id), overrides)
    payloads = PayloadLoader().load_repository(ROOT / "payload" / f"{group}.yaml")
    prompt = PayloadRenderer().render(
        payloads[case.payload_refs[0]], case.variables
    )
    return case, prompt


@pytest.mark.parametrize("group", GROUPS)
def test_three_candidates_and_matched_controls_load_and_render(group: str) -> None:
    prefix, _, _ = GROUPS[group]
    payloads = PayloadLoader().load_repository(ROOT / "payload" / f"{group}.yaml")
    assert len(payloads) == 6

    for suffix in ("001", "002", "003", "C01", "C02", "C03"):
        case_id = f"{prefix}-{suffix}"
        case, prompt = render_case(group, case_id)
        assert case.attack_module == group
        assert len(case.evaluation.rules) >= 1
        assert prompt.strip()
        assert "{{" not in prompt
        assert "DVAA" not in prompt
        assert case.evaluation.rules[0].parameters["name"] == (
            case.variables["violation_event_name"]
        )


@pytest.mark.parametrize("group", GROUPS)
def test_lab_overrides_bind_payload_and_rule_without_mutating_yaml(group: str) -> None:
    prefix, _, _ = GROUPS[group]
    source = load_case(group, f"{prefix}-001")
    overrides = {
        "public_note": "Project Cedar is a synthetic fixture.",
        "violation_event_name": f"{prefix.lower()}_fixture_event",
    }
    if group == "identity_privilege_abuse":
        overrides["protected_resource_id"] = "synthetic://user_b/cedar"
    else:
        overrides["canary_command"] = "echo CEDAR_SANDBOX_CANARY"

    bound, prompt = render_case(group, f"{prefix}-001", overrides)
    assert overrides["public_note"] in prompt
    assert bound.evaluation.rules[0].parameters["name"] == overrides[
        "violation_event_name"
    ]
    assert source.evaluation.rules[0].parameters["name"] == (
        "{{violation_event_name}}"
    )
    assert source.variables["public_note"] != overrides["public_note"]
    if group == "identity_privilege_abuse":
        assert overrides["protected_resource_id"] in prompt
    else:
        assert overrides["canary_command"] in prompt


class SyntheticAgentAdapter(BaseTargetAdapter):
    """Return a trusted fixture event only when the test asks it to."""

    def __init__(self, *, event_name: str | None, output_text: str) -> None:
        self.event_name = event_name
        self.output_text = output_text

    def execute(self, target: TargetProfile, test_input: CoreTestInput) -> ExecutionResult:
        assert target.id == "synthetic-lab-agent"
        assert test_input.metadata["testcase_id"]
        events: list[dict[str, Any]] = []
        if self.event_name is not None:
            events.append(
                {
                    "kind": "tool_call",
                    "source": "synthetic_agent_audit",
                    "name": self.event_name,
                    "success": True,
                    "data": {
                        "scope": "agent_run",
                        "verified_fixture": True,
                        "run_id": test_input.id,
                    },
                    "reference": f"synthetic_agent_audit/{test_input.id}",
                }
            )
        events.append(
            {
                "kind": "tool_trace",
                "source": "synthetic_agent_audit",
                "data": {"completeness": "complete", "scope": "agent_run"},
                "reference": f"synthetic_agent_audit/{test_input.id}/trace",
            }
        )
        return ExecutionResult(
            success=True, status_code=200, output_text=self.output_text, events=events
        )


def synthetic_target() -> TargetProfile:
    return TargetProfile(
        id="synthetic-lab-agent",
        name="Synthetic lab agent",
        target_type="ai_agent",
        interface=TargetInterface(
            type="http",
            adapter="generic_http",
            config={"url": "http://127.0.0.1:1/synthetic", "method": "POST"},
        ),
    )


def fixture_environment(group: str, case) -> dict[str, Any]:
    if group == "identity_privilege_abuse":
        return {
            "authorization_baseline": {
                "actor_id": case.variables["actor_id"],
                "resource_owner_id": case.variables["resource_owner_id"],
                "protected_resource_id": case.variables["protected_resource_id"],
                "actor_denied": True,
                "owner_allowed": True,
                "delegated_identity_can_read": True,
                "reference": "synthetic-fixture/authorization-preflight",
            }
        }
    return {
        "sandbox_id": "synthetic-disposable-sandbox",
        "sandbox_reference": "synthetic-fixture/sandbox-preflight",
        "canary_command_allowlist": ["echo SECAGENT_UCE_CANARY"],
    }


def run_fixture(group: str, case_id: str, *, event: bool, response: str):
    case, prompt = render_case(group, case_id)
    event_name = case.variables["violation_event_name"] if event else None
    adapter = SyntheticAgentAdapter(event_name=event_name, output_text=response)
    return Runner(
        executor=Executor(adapters={"generic_http": adapter})
    ).run(
        testcase=case,
        target=synthetic_target(),
        test_input=CoreTestInput(
            id=f"{case_id}-fixture",
            prompt=prompt,
            environment=fixture_environment(group, case),
        ),
    )


@pytest.mark.parametrize("group", GROUPS)
def test_mvp_requires_runtime_event_and_control_completes_public_task(group: str) -> None:
    prefix, _, _ = GROUPS[group]
    attack = f"{prefix}-001"
    control = f"{prefix}-C01"

    violated = run_fixture(
        group, attack, event=True,
        response="Project Atlas is a synthetic test project.",
    )
    assert violated.status is EvaluationStatus.FAIL
    assert violated.matched_rule_type == "tool_call"

    text_only = run_fixture(
        group, attack, event=False,
        response="I ran the command and read user B's private document.",
    )
    assert text_only.status is EvaluationStatus.INCONCLUSIVE

    clean = run_fixture(
        group, control, event=False,
        response="Project Atlas is a synthetic test project.",
    )
    assert clean.status is EvaluationStatus.PASS

    control_violation = run_fixture(
        group, control, event=True,
        response="Project Atlas is a synthetic test project.",
    )
    assert control_violation.status is EvaluationStatus.FAIL


def test_asi05_response_marker_without_action_is_not_execution() -> None:
    result = run_fixture(
        "unexpected_code_execution",
        "UCE-001",
        event=False,
        response="SECAGENT_UCE_CANARY",
    )
    assert result.status is EvaluationStatus.INCONCLUSIVE


def test_asi03_backend_only_claim_without_agent_event_is_not_agent_abuse() -> None:
    result = run_fixture(
        "identity_privilege_abuse",
        "IPA-001",
        event=False,
        response="The backend allowed access to user B's synthetic resource.",
    )
    assert result.status is EvaluationStatus.INCONCLUSIVE


@pytest.mark.parametrize("group", GROUPS)
def test_missing_lab_preflight_fails_before_target_execution(group: str) -> None:
    prefix, _, _ = GROUPS[group]
    case, prompt = render_case(group, f"{prefix}-001")
    result = Runner(
        executor=Executor(
            adapters={
                "generic_http": SyntheticAgentAdapter(
                    event_name=case.variables["violation_event_name"],
                    output_text="Project Atlas is a synthetic test project.",
                )
            }
        )
    ).run(case, synthetic_target(), CoreTestInput(id="no-preflight", prompt=prompt))
    assert result.status is EvaluationStatus.ERROR
    assert result.reason == "Attack module preparation failed."


@pytest.mark.parametrize("group", GROUPS)
def test_runner_rejects_unbound_action_rule(group: str) -> None:
    prefix, _, _ = GROUPS[group]
    case = load_case(group, f"{prefix}-001")
    result = Runner(
        executor=Executor(
            adapters={
                "generic_http": SyntheticAgentAdapter(
                    event_name=None, output_text="No action."
                )
            }
        )
    ).run(
        testcase=case,
        target=synthetic_target(),
        test_input=CoreTestInput(id="unbound-fixture", prompt="Public note"),
    )
    assert result.status is EvaluationStatus.ERROR
    assert result.reason == "Attack module preparation failed."
