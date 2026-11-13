"""Read-only Phase 2B.1 reporting; no evaluator or execution wiring."""
from reporting.models import ArchivedAssessmentReport, EvaluationReport, ExecutionReport, REPORT_ADAPTER
from reporting.normalizers import (
    NormalizationError, normalize_archived_assessment, normalize_native_report,
    normalize_report_bytes, normalize_report_file,
)


def evaluation_report_json_schema():
    """Return the schema in memory; no schema/artifact files are written."""
    return REPORT_ADAPTER.json_schema()


__all__ = ["ArchivedAssessmentReport", "EvaluationReport", "ExecutionReport", "NormalizationError",
    "normalize_archived_assessment", "normalize_native_report", "normalize_report_bytes",
    "normalize_report_file", "evaluation_report_json_schema"]
