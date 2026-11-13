"""Phase 2B.1 schema invariants; no execution/evaluation behavior changes."""
import pytest
from pydantic import ValidationError

from reporting import evaluation_report_json_schema, normalize_report_bytes
from reporting.models import (
    CategoryExtensions, CodeExecutionExtension, HistoricalSecurity, HumanReference, IdentityAccessExtension,
    REPORT_ADAPTER, ReportKind, ToolActionExtension, Verification,
)
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures/reporting"


@pytest.mark.parametrize("filename,kind", [("native-fail.json", "execution"), ("archived-agreement.json", "archived_assessment")])
def test_discriminated_models_round_trip(filename, kind):
    report = normalize_report_bytes((FIXTURES / filename).read_bytes())
    assert report.report_schema_version == "2.0.0" and report.report_kind == kind
    assert REPORT_ADAPTER.validate_json(report.model_dump_json()) == report


def test_schema_reserves_external_benchmark_without_accepting_imports():
    assert ReportKind.EXTERNAL_BENCHMARK.value == "external_benchmark"
    schema = evaluation_report_json_schema()
    assert set(schema["discriminator"]["mapping"]) == {"execution", "archived_assessment"}
    with pytest.raises(ValidationError): REPORT_ADAPTER.validate_python({"report_kind": "external_benchmark"})


@pytest.mark.parametrize("change", [{"performed_by_normalizer": True}, {"normalizer_status": "verified"}, {"independent_reverification": "verified"}])
def test_source_cannot_promote_normalizer_verification(change):
    with pytest.raises(ValidationError): Verification(**change)


def test_human_reference_has_a_separate_structural_contract():
    with pytest.raises(ValidationError): HumanReference(status="human_verified", label="FAIL")
    ref = HumanReference(status="human_verified", label="FAIL", reviewer_ref="reviewer-synthetic", verification_basis="review-note-1")
    assert ref.claim_repeated_by_normalizer is False
    assert HumanReference().status == "unavailable"


def test_future_asi_extensions_are_typed_facts_not_new_evaluators():
    extensions = CategoryExtensions(tool_action=ToolActionExtension(declared_name="tool", agent_origin="unknown"),
        identity_access=IdentityAccessExtension(actor_ref="synthetic-a", baseline_ref="baseline-1"),
        code_execution=CodeExecutionExtension(sandbox_ref="synthetic-box", command_sha256="a" * 64))
    assert extensions.tool_action.agent_origin == "unknown"
    with pytest.raises(ValidationError): CategoryExtensions(code_execution={"run_shell": "not allowed"})
    with pytest.raises(ValidationError): CodeExecutionExtension(command_sha256="not-a-hash")


def test_models_reject_untyped_new_fields_and_unknown_versions():
    report = normalize_report_bytes((FIXTURES / "native-control.json").read_bytes()).model_dump()
    report["report_schema_version"] = "3.0.0"
    with pytest.raises(ValidationError): REPORT_ADAPTER.validate_python(report)
    report["report_schema_version"] = "2.0.0"
    report["execute_target"] = True
    with pytest.raises(ValidationError): REPORT_ADAPTER.validate_python(report)


@pytest.mark.parametrize("historical,new", [("FAIL", "PASS"), ("ERROR", "FAIL")])
def test_models_cannot_rewrite_historical_security_verdict(historical, new):
    with pytest.raises(ValidationError): HistoricalSecurity(historical_status=historical, verdict=new, decisiveness="decisive")
