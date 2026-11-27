"""Bounded structured MCP cases through the existing Runner and action evaluator.

The case catalog is operator supplied. Imported chat prompts are never converted
to tool calls. Target-specific receipts are supplied by an optional observer
factory; the generic path records only SecAgent's request and target response.
"""

from hashlib import sha256
import ipaddress
import json
from pathlib import Path
from threading import Lock
from urllib.parse import urlsplit
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from core.models import TestCase, TestInput
from core.models.asi05_execution import Asi05ExecutionPolicy
from observers.mcp_direct_request_observer import McpDirectRequestObserver
from targets.adapters import McpJsonRpcTargetAdapter
from testing import Executor, Runner, RunnerEvaluationConfig
from workflow.catalog import make_profile, read_json
from workflow.dispatch import OneRequestHttpClient, sanitized
from workflow.persistence import write_atomic_bytes
from workflow.target_locks import (
    TargetExecutionConflictError,
    TargetExecutionLockRegistry,
    TargetLockHandle,
)


class McpActionRejected(ValueError):
    """A fixed, safe-to-report admission failure."""


class McpActionRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    testcase_id: str = Field(min_length=1, max_length=128)
    target_id: str = Field(min_length=1, max_length=128)
    profile_revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    catalog_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    evaluation_mode: str = Field(pattern=r"^(rule_only|hybrid)$")
    evidence_configuration: str = Field(pattern=r"^(request_only|configured_adapter)$")
    authorization_confirmed: bool


class StructuredMcpCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    testcase_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    asi_category: str = Field(pattern=r"^ASI05$")
    legitimate_objective: str = Field(min_length=1, max_length=1024)
    attacker_objective: str = Field(min_length=1, max_length=1024)
    target_id: str = Field(min_length=1, max_length=128)
    tool_name: str = Field(min_length=1, max_length=128)
    tool_arguments: dict
    expected_evidence: list[str] = Field(min_length=1, max_length=8)
    attribution: str = Field(pattern=r"^tool_service/direct_request$")
    execution_policy: Asi05ExecutionPolicy

    @model_validator(mode="after")
    def check_binding(self):
        policy = self.execution_policy
        signature = sha256(json.dumps(self.tool_arguments, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        actions = [*policy.authorized_actions, *policy.prohibited_actions]
        if (policy.testcase_id != self.testcase_id or policy.target_id != self.target_id
                or policy.subject != "tool_service" or not any(
                    action.tool_name == self.tool_name and action.arguments_sha256 == signature
                    for action in actions)):
            raise ValueError("Structured action and execution policy binding differ.")
        return self


def load_cases(path: Path) -> tuple[StructuredMcpCase, ...]:
    path = Path(path)
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 65536:
        raise McpActionRejected("mcp_case_catalog_unavailable")
    try:
        value = read_json(path.read_bytes())
        if not isinstance(value, dict) or set(value) != {"schema_version", "cases"} or value["schema_version"] != "1.0":
            raise ValueError
        rows = value["cases"]
        if not isinstance(rows, list) or not 1 <= len(rows) <= 20:
            raise ValueError
        cases = tuple(StructuredMcpCase.model_validate(row) for row in rows)
        if len({case.testcase_id for case in cases}) != len(cases):
            raise ValueError
        return cases
    except (ValueError, TypeError, KeyError):
        raise McpActionRejected("mcp_case_catalog_invalid") from None


class McpActionWorkflow:
    def __init__(self, catalog, output_root: Path, cases_path: Path, *,
                 hybrid_config: RunnerEvaluationConfig | None = None,
                 observer_factory=None, transport=None,
                 reviewed_catalog_sha256: str | None = None,
                 target_lock_registry: TargetExecutionLockRegistry | None = None):
        self.catalog = catalog
        self.output_root = Path(output_root)
        self.cases_path = Path(cases_path)
        self.cases = {case.testcase_id: case for case in load_cases(self.cases_path)}
        self.catalog_sha256 = sha256(self.cases_path.read_bytes()).hexdigest()
        if any(case.execution_policy.review_status == "reviewed" for case in self.cases.values()) and (
                reviewed_catalog_sha256 != self.catalog_sha256):
            raise McpActionRejected("reviewed_mcp_catalog_pin_required")
        self.hybrid_config = hybrid_config
        self.observer_factory = observer_factory
        self.transport = transport
        self.target_locks: TargetExecutionLockRegistry | None = target_lock_registry
        self._lock = Lock()

    def public_cases(self):
        return [{"testcase_id": case.testcase_id, "asi_category": case.asi_category,
            "evaluation_scope": "execution_action", "legitimate_objective": case.legitimate_objective,
            "attacker_objective": case.attacker_objective, "target_id": case.target_id,
            "tool_name": case.tool_name, "arguments_sha256": sha256(json.dumps(
                case.tool_arguments, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "expected_evidence": case.expected_evidence, "attribution": case.attribution,
            "policy_id": case.execution_policy.policy_id,
            "policy_revision_sha256": case.execution_policy.revision_sha256,
            "policy_status": case.execution_policy.review_status,
            "evidence_status": "partial_until_correlated_receipt_verified",
            "adapter_evidence_available": bool(self.observer_factory and
                getattr(self.observer_factory, "supports_target", lambda _: False)(
                    self.catalog._targets.get(case.target_id))),
            "judge_status": "deterministic_action_scope_no_pi_skill",
            "official_verdict_eligible": False}
            for case in self.cases.values()]

    def run(self, *, case_id: str, target_id: str, profile_revision: str,
            catalog_sha256: str, authorization_confirmed: bool,
            evaluation_mode: str = "rule_only",
            evidence_configuration: str = "request_only"):
        if authorization_confirmed is not True:
            raise McpActionRejected("mcp_action_authorization_required")
        if evaluation_mode not in {"rule_only", "hybrid"}:
            raise McpActionRejected("mcp_action_evaluation_mode_invalid")
        if evaluation_mode == "hybrid" and self.hybrid_config is None:
            raise McpActionRejected("mcp_action_hybrid_unavailable")
        if evidence_configuration not in {"request_only", "configured_adapter"}:
            raise McpActionRejected("mcp_action_evidence_configuration_invalid")
        if (catalog_sha256 != self.catalog_sha256 or not self.cases_path.is_file()
                or self.cases_path.is_symlink() or self.cases_path.stat().st_size > 65536
                or sha256(self.cases_path.read_bytes()).hexdigest() != self.catalog_sha256):
            raise McpActionRejected("mcp_case_catalog_changed")
        case = self.cases.get(case_id)
        if case is None or case.target_id != target_id:
            raise McpActionRejected("mcp_case_target_mismatch")
        preset = self.catalog._targets.get(target_id)
        if (preset is None or not preset.reviewed or preset.protocol != "mcp-jsonrpc"
                or self.catalog._revisions.get(target_id) != profile_revision
                or preset.credential_alias is not None):
            raise McpActionRejected("mcp_target_not_reviewed_or_stale")
        if evidence_configuration == "configured_adapter" and (self.observer_factory is None
                or not getattr(self.observer_factory, "supports_target", lambda _: False)(preset)):
            raise McpActionRejected("mcp_action_evidence_adapter_unavailable")
        try:
            url = urlsplit(preset.endpoint)
            address = ipaddress.ip_address(url.hostname or "")
            if (url.scheme != "http" or not address.is_loopback or url.port is None
                    or url.path not in {"/", "/mcp", "/jsonrpc"}
                    or url.username or url.password or url.query or url.fragment):
                raise ValueError
        except ValueError:
            raise McpActionRejected("mcp_endpoint_not_local") from None
        if not self._lock.acquire(blocking=False):
            raise McpActionRejected("mcp_action_run_active")
        shared_lock_handle: TargetLockHandle | None = None
        try:
            execution_id = uuid4().hex
            if self.target_locks is not None:
                try:
                    shared_lock_handle = self.target_locks.reserve(
                        [target_id],
                        endpoints=[preset.endpoint],
                        owner_kind="mcp_action",
                        run_id=execution_id,
                        conflict_code="target_execution_in_progress",
                    )
                except TargetExecutionConflictError:
                    raise McpActionRejected("target_execution_in_progress") from None
            run_dir = self.output_root / ("mcp-action-" + execution_id)
            run_dir.mkdir(parents=True, exist_ok=False)  # Reserve report location before network.
            target = make_profile(preset, preset.default_model, preset.timeout_default)
            target.interface.config["asi05_live_evidence"] = True
            testcase = TestCase(id=case.testcase_id, name=case.testcase_id,
                category="unexpected_code_execution", attack_module="asi05_direct_mcp",
                objective=case.attacker_objective,
                variables={"asi05_execution_id": execution_id},
                evaluation={"strategy": "action", "rules": [], "semantic": {
                    "enabled": True, "skill": "unexpected_code_execution",
                    "trusted_context": {"evaluation_scope": "execution_action",
                        "asi05_execution_policy": case.execution_policy.model_dump(mode="json"),
                        "legitimate_objective": case.legitimate_objective},
                    "expected_labels": ["POLICY_VIOLATION", "POLICY_PRESERVED", "UNCLEAR"]}})
            test_input = TestInput(id=execution_id, parameters={"tool_call": {
                "name": case.tool_name, "arguments": case.tool_arguments}})
            observer = (self.observer_factory(testcase, target, test_input)
                        if evidence_configuration == "configured_adapter" else None)
            if evidence_configuration == "configured_adapter" and observer is None:
                raise McpActionRejected("mcp_action_evidence_adapter_unavailable")
            observer = observer or McpDirectRequestObserver.for_target(testcase, target, test_input)
            client = OneRequestHttpClient(preset.endpoint, preset.timeout_default, transport=self.transport)
            # The existing HybridEvaluator owns the execution-action evidence
            # branch. A rule-only operator choice disables Pi, not that branch.
            runner = Runner(executor=Executor({"generic_mcp_jsonrpc": McpJsonRpcTargetAdapter(client)}),
                observer=observer, evaluation_config=(self.hybrid_config if evaluation_mode == "hybrid"
                    else RunnerEvaluationConfig(mode="hybrid")))
            verdict = runner.run(testcase, target, test_input)
            report = runner.last_report
            observation = report.get("observation") or {}
            response_text = observation.get("response_text")
            if isinstance(response_text, str):
                observation["response_sha256"] = sha256(response_text.encode()).hexdigest()
                observation["response_text"] = "[REDACTED_MCP_TOOL_RESULT]"
            result = {"testcase_id": case_id, "execution_id": execution_id,
                "target_id": target_id, "profile_revision": profile_revision,
                "catalog_sha256": self.catalog_sha256, "target_request_count": client.used,
                "evaluation_scope": "execution_action", "attribution": "tool_service/direct_request",
                "evidence_configuration": evidence_configuration,
                "final_verdict": verdict.status.value,
                "policy_status": case.execution_policy.review_status,
                "semantic_invoked": bool((report.get("judge") or {}).get("semantic_invoked")),
                "report_path": str(run_dir / "native_report.json")}
            safe_report = sanitized(report)
            report_bytes = (json.dumps(safe_report, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
            write_atomic_bytes(run_dir / "native_report.json", report_bytes)
            summary_bytes = (json.dumps({
                "run_id": execution_id, "report_file": "native_report.json",
                "report_sha256": sha256(report_bytes).hexdigest(),
                "native_execution_id": safe_report["run_id"],
                "testcase_id": case_id, "target_id": target_id,
                "report_persisted": True, "report_kind": "mcp_action",
                "target_request_count": client.used}, sort_keys=True) + "\n").encode("utf-8")
            write_atomic_bytes(run_dir / "run-summary.json", summary_bytes)
            return result
        finally:
            if shared_lock_handle is not None and self.target_locks is not None:
                self.target_locks.release(shared_lock_handle)
            self._lock.release()
