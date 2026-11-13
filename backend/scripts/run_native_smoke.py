"""Run one existing native testcase against one configured target."""

import argparse
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = REPOSITORY_ROOT / "backend" / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from core.models import (
    EvaluationResult,
    EvaluationStatus,
    ExecutionResult,
    TargetProfile,
    TestCase,
    TestInput,
)
from payloads import PayloadLoader, PayloadRenderer
from targets import load_target
from targets.runtime import build_runtime_target, RuntimeTargetError
from testing import Executor, Runner, TestCaseLoader, RunnerEvaluationConfig
from integrations.external_evaluator import PiEvaluatorConfig
from testing.web_fixture import WebFixture, now


DEFAULT_OUTPUT_DIR = REPOSITORY_ROOT / "results" / "smoke" / "week5"
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
                self.last_result.events.append({"kind": "collector_diagnostic", "source": "local_collector",
                    "data": {"status": "invalid_or_unavailable", "observation_complete": False}})
        return self.last_result


def safe_identifier(value: str) -> str:
    """Allow only simple identifiers in evidence and filenames."""

    if not SAFE_IDENTIFIER.fullmatch(value):
        raise ValueError("Smoke evidence requires simple testcase and target identifiers.")
    return value


def build_test_input(testcase: TestCase, target: TargetProfile) -> TestInput:
    """Render the existing payload for the configured transport."""

    category = safe_identifier(testcase.category)
    if len(testcase.payload_refs) != 1:
        raise ValueError("A native smoke testcase must reference exactly one payload.")

    payloads = PayloadLoader().load_repository(
        REPOSITORY_ROOT / "payload" / f"{category}.yaml"
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


def run_smoke(
    target_config: Path | None,
    testcase_path: Path,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
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
) -> tuple[Path, dict[str, object]]:
    """Run one testcase through Runner and write one sanitized summary."""

    testcase = TestCaseLoader().load(testcase_path)
    if (target_config is None) == (target_profile is None):
        raise ValueError("Supply exactly one target configuration or runtime profile.")
    target = target_profile if target_profile is not None else load_target(target_config)
    fixture = WebFixture(web_fixture_run) if web_fixture_run is not None else None
    if fixture:
        if prompt_file is not None:
            raise ValueError("Fixture runs must use the official payload, not --prompt-file.")
        testcase = fixture.bind(testcase, target.id)
    elif testcase.evaluation.semantic and testcase.evaluation.semantic.trusted_context.get("collector_verification_required") is True:
        raise ValueError("This testcase requires --web-fixture-run for independent correlation.")
    test_input = (TestInput(id=f"native-manual-{safe_identifier(testcase.id)}",
        prompt=prompt_file.read_text(encoding="utf-8")) if prompt_file else build_test_input(testcase, target))
    recording_executor = RecordingExecutor(executor, fixture)
    runner = Runner(executor=recording_executor, evaluation_config=evaluation_config, judge_provider=judge_provider)
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


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--target-config", type=Path)
    target_group.add_argument("--target-url", help="Complete OpenAI-compatible chat endpoint URL")
    parser.add_argument("--target-id")
    parser.add_argument("--target-protocol", default="openai-chat")
    parser.add_argument("--authorized-lab-origin", help="Explicitly authorized HTTP(S) origin, including port")
    parser.add_argument("--target-model", default="default")
    parser.add_argument("--target-credential-env", help="Environment variable containing the complete Authorization header")
    parser.add_argument("--discover-target", action="store_true", help="Optional same-origin /health request")
    parser.add_argument("--testcase", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--prompt-file", type=Path, help="Explicit manual input; bypass payload repository rendering")
    parser.add_argument("--web-fixture-run", type=Path, help="Operator-controlled local fixture run directory; read independent receipts")
    parser.add_argument("--evaluation-mode", choices=["rule_only", "hybrid"], default="rule_only")
    parser.add_argument("--enable-judge", action="store_true")
    parser.add_argument("--allow-live-judge", action="store_true", help="Explicit approval/opt-in for configured live Judge calls")
    parser.add_argument("--max-judge-calls", type=int, default=0)
    parser.add_argument("--pi", default="pi")
    parser.add_argument("--judge-provider", default="deepseek")
    parser.add_argument("--judge-model", default="deepseek-v4-flash")
    parser.add_argument("--judge-timeout", type=float, default=90)
    parser.add_argument("--judge-max-output-bytes", type=int, default=65536)
    parser.add_argument("--judge-credential-env", action="append", default=None)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None, *, executor: Executor | None = None) -> int:
    args = parse_args(argv)
    try:
        target_profile = None
        if args.target_url:
            if not args.target_id or not args.authorized_lab_origin:
                raise RuntimeTargetError("Runtime URLs require --target-id and --authorized-lab-origin.")
            target_profile = build_runtime_target(args.target_url, args.target_id,
                protocol=args.target_protocol, authorized_origin=args.authorized_lab_origin,
                model=args.target_model, credential_env=args.target_credential_env,
                discover=args.discover_target)
        elif (args.target_id or args.authorized_lab_origin or args.target_credential_env
                or args.discover_target or args.target_protocol != "openai-chat" or args.target_model != "default"):
            raise RuntimeTargetError("Runtime target options require --target-url.")
        config = RunnerEvaluationConfig(mode=args.evaluation_mode,
            judge_enabled=args.enable_judge, allow_live_judge=args.allow_live_judge,
            max_judge_calls=args.max_judge_calls,
            pi=PiEvaluatorConfig(executable=args.pi, provider=args.judge_provider, model=args.judge_model,
                timeout_seconds=args.judge_timeout, max_output_bytes=args.judge_max_output_bytes,
                credential_env=tuple(args.judge_credential_env or ["DEEPSEEK_API_KEY"])))
        output_path, summary = run_smoke(
            args.target_config, args.testcase, args.output_dir, executor=executor,
            evaluation_config=config, prompt_file=args.prompt_file,
            target_profile=target_profile,
            web_fixture_run=args.web_fixture_run,
        )
    except RuntimeTargetError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except Exception as exc:
        print(
            f"Native smoke failed before evidence was written ({type(exc).__name__}).",
            file=sys.stderr,
        )
        return 1

    print(output_path)
    print(
        f"execution={summary['smoke_execution_succeeded']} "
        f"evaluation={summary['evaluation_status']}",
        file=sys.stderr,
    )
    return 0 if (
        summary["smoke_execution_succeeded"]
        and summary["evaluation_status"] != EvaluationStatus.ERROR.value
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
