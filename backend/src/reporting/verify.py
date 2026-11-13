"""Print opt-in verification metadata and normalized reports; never writes artifacts."""
import argparse
import json
import sys

from reporting.artifacts import ArchiveVerificationError, verify_archive


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", help="Explicit local archive root containing all selected artifacts")
    parser.add_argument("--inventory", required=True, help="Root-relative evidence-sha256.csv")
    parser.add_argument("--execution", required=True, help="Root-relative original native report")
    parser.add_argument("--assessment", help="Root-relative archived cross-check report")
    args = parser.parse_args(argv)
    try:
        result = verify_archive(args.root, inventory=args.inventory, execution=args.execution, assessment=args.assessment)
    except (ArchiveVerificationError, OSError):
        print("Archive verification rejected: unsafe, malformed or unavailable input; raw details omitted.", file=sys.stderr)
        return 2
    print(json.dumps(result.model_dump(mode="json"), ensure_ascii=True, indent=2, allow_nan=False))
    states = result.verification
    return 0 if (states.file_integrity == states.internal_evidence_consistency == "verified"
                 and states.crosscheck_linkage in {"verified", "not_performed"}
                 and all(v not in {"mismatch", "missing", "unsupported"} for k, v in states.checks.items()
                         if k.startswith("crosscheck_"))) else 1


if __name__ == "__main__":
    raise SystemExit(main())
