"""Explicit-file, stdout-only CLI for the pure reporting aggregator."""
import argparse
import json
from pathlib import Path
import sys

from reporting.aggregation import AggregationError, aggregate_reports
from reporting.artifacts import ArchiveReader, ArchiveVerificationError, verify_archive
from reporting.models import ArchivedAssessmentReport, ExecutionReport
from reporting.normalizers import NormalizationError, normalize_report_bytes


def _load(path, expected):
    path = Path(path).absolute()
    reader = ArchiveReader(path.parent)
    raw = reader.read(reader.path(path.name))
    if raw is None:
        raise AggregationError("Selected source missing.")
    record = normalize_report_bytes(raw)
    if not isinstance(record, expected):
        raise AggregationError("Wrong selected report kind.")
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execution", action="append", default=[], help="Explicit native execution source; repeatable")
    parser.add_argument("--assessment", action="append", default=[], help="Explicit archived assessment source; repeatable")
    parser.add_argument("--verify-root", help="Optional explicit root for the existing Phase 2B.2 verifier")
    parser.add_argument("--verify-inventory", help="Root-relative inventory for optional verification")
    parser.add_argument("--verify-execution", help="Root-relative execution for optional verification")
    parser.add_argument("--verify-assessment", help="Root-relative assessment for optional verification")
    args = parser.parse_args(argv)
    if any((args.verify_root, args.verify_inventory, args.verify_execution, args.verify_assessment)) and not all(
            (args.verify_root, args.verify_inventory, args.verify_execution)):
        parser.error("Optional verification requires root, inventory and execution together.")
    if not (args.execution or args.assessment or args.verify_root):
        parser.error("Select at least one execution or assessment explicitly.")
    try:
        records = [_load(path, ExecutionReport) for path in args.execution]
        records += [_load(path, ArchivedAssessmentReport) for path in args.assessment]
        if args.verify_root:
            bundle = verify_archive(args.verify_root, inventory=args.verify_inventory, execution=args.verify_execution,
                                    assessment=args.verify_assessment)
            records += [r for r in (bundle.execution, bundle.assessment) if r is not None]
            if bundle.execution is None or (args.verify_assessment and bundle.assessment is None):
                raise AggregationError("Required verified selection missing.")
        result = aggregate_reports(records)
    except (AggregationError, ArchiveVerificationError, NormalizationError, OSError, ValueError, RecursionError):
        print("Aggregation rejected: missing, malformed, unsafe or conflicting selected reports; raw details omitted.", file=sys.stderr)
        return 2
    print(json.dumps(result.model_dump(mode="json"), ensure_ascii=True, indent=2, allow_nan=False))
    # A security FAIL or a linkage mismatch is data, not a CLI execution error.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
