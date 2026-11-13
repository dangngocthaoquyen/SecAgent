"""Print one normalized report to stdout. No output-file or execution options."""
import argparse
import json
import os
import sys

from reporting import NormalizationError, normalize_report_file


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", help="Existing native or archived cross-check JSON file")
    parser.add_argument("--redact-env", action="append", default=[], metavar="NAME",
        help="Optional environment variable NAME containing an additional value to redact; never pass the value")
    args = parser.parse_args(argv)
    try:
        values = tuple(os.environ[name] for name in args.redact_env if os.environ.get(name))
        report = normalize_report_file(args.source, redact_values=values)
    except (NormalizationError, OSError):
        print("Normalization rejected: missing, unsupported, ambiguous or malformed source report; raw contents omitted.", file=sys.stderr)
        return 1
    # ASCII JSON escapes remain lossless through older Windows PowerShell pipes.
    print(json.dumps(report.model_dump(mode="json"), ensure_ascii=True, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
