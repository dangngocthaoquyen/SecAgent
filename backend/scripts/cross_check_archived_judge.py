"""Assess a hash-verified archived observation; never execute/replay its target."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from integrations.external_evaluator import PiEvaluatorConfig, PiEvaluatorProvider
from integrations.external_evaluator.validation import LABEL_VERDICTS
from testing.archived_crosscheck import ArchiveError, prepare_cross_check, write_cross_check
from testing.evaluation_config import BudgetedJudgeProvider, RunnerEvaluationConfig
from validate_independent_judge import FakeJudge


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive-dir", type=Path, required=True)
    parser.add_argument("--testcase", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--mode", choices=["validate", "fake", "live"], default="validate")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--allow-live-judge", action="store_true")
    parser.add_argument("--max-judge-calls", type=int, choices=[0, 1], default=0)
    parser.add_argument("--pi", default="pi")
    parser.add_argument("--judge-provider", default="deepseek")
    parser.add_argument("--judge-model", default="deepseek-v4-pro")
    parser.add_argument("--judge-timeout", type=float, default=90)
    parser.add_argument("--judge-credential-env", action="append", default=None)
    parser.add_argument("--fake-classification", default="UNCLEAR")
    args = parser.parse_args(argv)
    try:
        if args.mode == "live" and (not args.allow_live_judge or args.max_judge_calls != 1):
            raise ValueError("Live mode requires explicit opt-in and a one-call budget.")
        if args.mode != "live" and args.allow_live_judge:
            raise ValueError("Live opt-in requires live mode.")
        if args.mode != "validate" and (args.output is None or args.max_judge_calls != 1):
            raise ValueError("Assessment requires a new output path and a one-call budget.")
        prepared = prepare_cross_check(args.archive_dir, args.testcase, report_path=args.report,
            credential_env=tuple(args.judge_credential_env or ["DEEPSEEK_API_KEY"]))
        if args.mode == "validate":
            print(json.dumps({"archive_valid": True, "verified_files": len(prepared.files),
                "testcase_id": prepared.original["testcase_id"], "fixture_correlation_id": prepared.original["fixture_correlation_id"],
                "request_canonical_sha256": prepared.request.sha256, "provider_invoked": False,
                "target_execution_performed": False}))
            return 0
        pi = PiEvaluatorConfig(executable=args.pi, provider=args.judge_provider, model=args.judge_model,
            timeout_seconds=args.judge_timeout, credential_env=tuple(args.judge_credential_env or ["DEEPSEEK_API_KEY"]))
        transport = None
        if args.mode == "fake":
            mapping = LABEL_VERDICTS[prepared.request.evaluation_type]
            if args.fake_classification not in prepared.request.expected_labels:
                raise ValueError("Unsupported fake classification.")
            response = {"classification": args.fake_classification, "verdict": mapping[args.fake_classification].value,
                "confidence": 0.5, "reason": "Canned offline response, not independent Judge accuracy evidence.",
                "evidence": [{"type": "response_span", "value": prepared.request.observation.response_text}]
                    if prepared.request.observation.response_text else []}
            transport = FakeJudge({prepared.request.request_id: json.dumps(response)})
        provider = PiEvaluatorProvider(pi, process_runner=transport)
        config = RunnerEvaluationConfig(mode="hybrid", judge_enabled=True, max_judge_calls=1,
            allow_live_judge=args.mode == "live", pi=pi)
        budget = BudgetedJudgeProvider(config, provider)
        result = write_cross_check(prepared, args.output, budget, provider_name=args.judge_provider,
            model=args.judge_model, mode=args.mode)
        print(json.dumps({"output": str(args.output), "comparison": result["comparison"]["status"],
            "json_validation_status": result["judge"]["json_validation_status"], "provider_calls_used": budget.used,
            "target_execution_performed": False}))
        return 0 if result["archive_integrity_unchanged_after_assessment"] and result["judge"]["json_validation_status"] == "valid" else 1
    except ArchiveError as exc:
        print("Cross-check rejected: " + str(exc), file=sys.stderr)
        return 1
    except Exception:
        # Never echo arbitrary archive text, keys, private paths or provider stderr.
        print("Cross-check rejected or failed. Check archive integrity, identity, semantic support, invocation flags and output exclusivity; raw diagnostics omitted.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
