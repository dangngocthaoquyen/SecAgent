"""Run a no-network Garak smoke scan through SecAgent's provider."""

import argparse
import os
import sys
from datetime import UTC, datetime
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = REPOSITORY_ROOT / "backend" / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from integrations.security_tools import (
    GarakProvider,
    GarakRunConfig,
)
from integrations.security_tools.smoke_summary import write_smoke_summary


def parse_args() -> argparse.Namespace:
    """Parse development-only smoke options."""

    parser = argparse.ArgumentParser(
        description="Run Garak's built-in test probe through GarakProvider.",
    )
    parser.add_argument(
        "--executable",
        default=os.environ.get(
            "GARAK_EXECUTABLE",
            "garak",
        ),
        help=(
            "Path to the Garak executable. Defaults to GARAK_EXECUTABLE, then "
            "garak on PATH."
        ),
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=120.0,
        help="Finite subprocess timeout for the smoke run (default: 120).",
    )
    return parser.parse_args()


def main() -> int:
    """Run the built-in Garak smoke scan and print its normalized result."""

    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = parse_args()
    report_directory = REPOSITORY_ROOT / "results" / "smoke" / "week4"
    report_directory.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    report_prefix = report_directory / f"garak-built-in-{timestamp}"

    config = GarakRunConfig(
        target_type="test.Blank",
        spec="probes.test.Test",
        generations=1,
        report_prefix=str(report_prefix),
        timeout_seconds=args.timeout_seconds,
    )
    result = GarakProvider(
        executable=args.executable,
        config=config,
    ).run()
    summary_path = write_smoke_summary(
        result,
        report_prefix,
        REPOSITORY_ROOT,
    )

    print(result.model_dump_json(indent=2))
    print(f"SecAgent smoke summary written to {summary_path}", file=sys.stderr)
    print(
        "Garak success reports process completion only; it is not a SecAgent "
        "security verdict.",
        file=sys.stderr,
    )

    smoke_succeeded = (
        result.tool_name == "garak"
        and result.success
        and result.exit_code == 0
        and bool(result.artifacts)
        and summary_path.is_file()
    )
    return 0 if smoke_succeeded else 1


if __name__ == "__main__":
    raise SystemExit(main())
