"""Canonical native execution recording and sanitized summary builders."""

from datetime import UTC, datetime
import json
from pathlib import Path
import re

from core.models import (
    EvaluationResult,
    ExecutionResult,
    TargetProfile,
    TestCase,
    TestInput,
)
from payloads import PayloadLoader, PayloadRenderer
from targets import load_target
from testing.evaluation_config import RunnerEvaluationConfig
from testing.executor import Executor
from testing.runner import Runner
from testing.testcase_loader import TestCaseLoader
from testing.web_fixture import WebFixture, now


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SAFE_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")


class RecordingExecutor(Executor):
    """Delegate to Executor while retaining only its result in memory."""

    def __init__(self, delegate: Executor | None = None, fixture: WebFixture | None = None) -> None:
        self._delegate = delegate if delegate is not None else Executor()
        self.last_result: ExecutionResult | None = None
        self._fixture = fixture

    def execute(self, target: TargetProfile, test_input: TestInput) -> ExecutionResult:
        if self._fixture:
            self._fixture.claim()
        started = now()
        self.last_result = self._delegate.execute(target, test_input)
        ended = now()
        if self._fixture:
            try:
                self.last_result.events.append(self._fixture.evidence(started, ended))
            except (OSError, ValueError, TypeError, KeyError):
                self.last_result.events.append({
                    "kind": "collector_diagnostic",
                    "source": "local_collector",
                    "data": {"status": "invalid_or_unavailable", "observation_complete": False},
                })
        return self.last_result


def safe_identifier(value: str) -> str:
    """Allow only simple identifiers in evidence and filenames."""

    if not SAFE_IDENTIFIER.fullmatch(value):
        raise ValueError("Smoke evidence requires simple testcase and target identifiers.")
    return value


def build_test_input(
    testcase: TestCase,
    target: TargetProfile,
    *,
    repository_root: Path = REPOSITORY_ROOT,
) -> TestInput:
    """Render the existing payload for the configured transport."""

    category = safe_identifier(testcase.category)
    if len(testcase.payload_refs) != 1:
        raise ValueError("A native smoke testcase must reference exactly one payload.")

    payloads = PayloadLoader().load_repository(
        Path(repository_root) / "payload" / f"{category}.yaml"
    )
    payload = payloads[testcase.payload_refs[0]]
    if payload.category != testcase.category:
        raise ValueError("Payload and testcase categories do not match.")
    rendered = PayloadRenderer().render(payload, testcase.variables)

    parameters: dict[str, object] = {}
    if target.interface.adapter == "generic_mcp_jsonrpc":
        tool_name = testcase.variables.get("tool_name")
        if not isinstance(tool_name, str) or not tool_name.strip():
            raise ValueError("MCP smoke testcase requires a tool_name variable.")
        parameters = {
            "tool_call": {
                "name": tool_name,
                "arguments": {"command": rendered},
            }
        }

    return TestInput(
        id=f"native-smoke-{safe_identifier(testcase.id)}",
        prompt=rendered,
        payload_ref=payload.id,
        parameters=parameters,
    )


def build_summary(
    testcase: TestCase,
    target: TargetProfile,
    evaluation: EvaluationResult,
    execution: ExecutionResult | None,
    timestamp: datetime,
) -> dict[str, object]:
    """Build allowlisted black-box evidence without raw request or response data."""

    return {
        "engine": "native",
        "timestamp": timestamp.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "testcase_id": safe_identifier(testcase.id),
        "category": safe_identifier(testcase.category),
        "attack_module": safe_identifier(testcase.attack_module),
        "target_id": safe_identifier(target.id),
        "adapter": safe_identifier(target.interface.adapter),
        "smoke_execution_succeeded": execution is not None and execution.success,
        "evaluation_status": evaluation.status.value,
        "black_box_evidence_semantics": {
            "scope": "black_box",
            "observes": "Adapter-visible response or direct MCP result only.",
            "limitation": "No internal agent trace or private target context is observed.",
        },
    }


def run_native_report(
    target_config: Path | None,
    testcase_path: Path,
    output_dir: Path,
    *,
    executor: Executor | None = None,
    timestamp: datetime | None = None,
    evaluation_config: RunnerEvaluationConfig | None = None,
    judge_provider=None,
    prompt_file: Path | None = None,
    target_profile: TargetProfile | None = None,
    web_fixture_run: Path | None = None,
    sanitize_summary=None,
    source_provenance: str | None = None,
    repository_root: Path = REPOSITORY_ROOT,
    testcase_loader: TestCaseLoader | None = None,
    target_loader=load_target,
) -> tuple[Path, dict[str, object]]:
    """Run one testcase through Runner and write one sanitized summary."""

    loader = testcase_loader if testcase_loader is not None else TestCaseLoader()
    testcase = loader.load(testcase_path)
    if (target_config is None) == (target_profile is None):
        raise ValueError("Supply exactly one target configuration or runtime profile.")
    target = target_profile if target_profile is not None else target_loader(target_config)
    fixture = WebFixture(web_fixture_run) if web_fixture_run is not None else None
    if fixture:
        if prompt_file is not None:
            raise ValueError("Fixture runs must use the official payload, not --prompt-file.")
        testcase = fixture.bind(testcase, target.id)
    elif testcase.evaluation.semantic and testcase.evaluation.semantic.trusted_context.get("collector_verification_required") is True:
        raise ValueError("This testcase requires --web-fixture-run for independent correlation.")
    test_input = (
        TestInput(
            id=f"native-manual-{safe_identifier(testcase.id)}",
            prompt=prompt_file.read_text(encoding="utf-8"),
        )
        if prompt_file
        else build_test_input(testcase, target, repository_root=repository_root)
    )
    recording_executor = RecordingExecutor(executor, fixture)
    runner = Runner(
        executor=recording_executor,
        evaluation_config=evaluation_config,
        judge_provider=judge_provider,
    )
    evaluation = runner.run(testcase, target, test_input)
    run_time = timestamp if timestamp is not None else datetime.now(UTC)
    summary = build_summary(
        testcase, target, evaluation, recording_executor.last_result, run_time
    )
    summary["evaluation"] = runner.last_report
    if source_provenance is not None:
        if source_provenance != "synthetic_mock":
            raise ValueError("Unsupported source provenance marker.")
        summary["source_provenance"] = source_provenance
        summary["black_box_evidence_semantics"]["limitation"] = (
            "Synthetic local mock target and fixture; this is not a DVAA security finding."
        )
    if sanitize_summary is not None:
        summary = sanitize_summary(summary)

    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = run_time.astimezone(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    output_path = output_dir / (
        f"native-{stamp}-{summary['testcase_id']}-{summary['target_id']}.secagent.json"
    )
    with output_path.open("x", encoding="utf-8") as evidence_file:
        json.dump(summary, evidence_file, indent=2)
        evidence_file.write("\n")
    return output_path, summary
