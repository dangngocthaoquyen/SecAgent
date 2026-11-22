"""Run one existing native testcase against one configured target."""

import argparse
import sys
from datetime import datetime
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
from targets import load_target
from targets.runtime import build_runtime_target, RuntimeTargetError
from testing import Executor, TestCaseLoader, RunnerEvaluationConfig
from testing.report_builder import (
    RecordingExecutor,
    SAFE_IDENTIFIER,
    build_summary,
    build_test_input,
    run_native_report,
    safe_identifier,
)
from integrations.external_evaluator import PiEvaluatorConfig


DEFAULT_OUTPUT_DIR = REPOSITORY_ROOT / "results" / "smoke" / "week5"


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

    return run_native_report(
        target_config,
        testcase_path,
        output_dir,
        executor=executor,
        timestamp=timestamp,
        evaluation_config=evaluation_config,
        judge_provider=judge_provider,
        prompt_file=prompt_file,
        target_profile=target_profile,
        web_fixture_run=web_fixture_run,
        sanitize_summary=sanitize_summary,
        source_provenance=source_provenance,
        repository_root=REPOSITORY_ROOT,
        testcase_loader=TestCaseLoader(),
        target_loader=load_target,
    )


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
