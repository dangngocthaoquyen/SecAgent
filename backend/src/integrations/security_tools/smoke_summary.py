"""Normalized evidence helpers for external security tool smoke runs."""

import json
from pathlib import Path

from integrations.security_tools.models import ExternalToolResult


SAFE_SUMMARY_METADATA_KEYS = (
    "target_type",
    "spec",
    "generations",
    "report_prefix",
)


def normalize_evidence_path(value: str, repository_root: Path) -> str:
    """Return a portable path without exposing an absolute machine location."""

    path = Path(value)
    candidate = path if path.is_absolute() else repository_root / path
    try:
        return candidate.resolve().relative_to(repository_root).as_posix()
    except ValueError:
        return path.name


def build_smoke_summary(
    result: ExternalToolResult,
    repository_root: Path,
) -> dict[str, object]:
    """Build small, non-sensitive evidence for one tool smoke process."""

    safe_metadata = {
        key: (
            normalize_evidence_path(result.metadata[key], repository_root)
            if key == "report_prefix"
            and isinstance(result.metadata[key], str)
            else result.metadata[key]
        )
        for key in SAFE_SUMMARY_METADATA_KEYS
        if key in result.metadata
    }
    return {
        "tool_name": result.tool_name,
        "success": result.success,
        "exit_code": result.exit_code,
        "error": result.error,
        "artifacts": [
            normalize_evidence_path(path, repository_root)
            for path in result.artifacts
        ],
        "metadata": safe_metadata,
        "success_semantics": {
            "means": "The external Garak process execution succeeded.",
            "does_not_mean": [
                "The target is secure.",
                "A vulnerability test passed.",
                "The SecAgent security verdict is PASS.",
            ],
        },
    }


def write_smoke_summary(
    result: ExternalToolResult,
    report_prefix: Path,
    repository_root: Path,
) -> Path:
    """Write normalized SecAgent smoke evidence next to tool reports."""

    summary_path = Path(f"{report_prefix}.secagent.json")
    summary_path.write_text(
        json.dumps(
            build_smoke_summary(result, repository_root),
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    return summary_path
