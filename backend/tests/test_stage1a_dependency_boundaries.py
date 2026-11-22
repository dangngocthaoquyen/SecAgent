"""Regression contracts for Stage 1A dependency boundary refactoring."""

import ast
from datetime import datetime, timezone
import os
from pathlib import Path
import subprocess
import sys

import pytest

from backend.scripts import run_native_smoke
from core.models import (
    EvaluationResult,
    EvaluationStatus,
    ExecutionResult,
    TargetProfile,
    TestCase as NativeTestCase,
    TestInput as NativeTestInput,
)
from testing import Executor, TestCaseLoader
from testing import report_builder
from workflow import web_lab_assets, web_mock_batch
from workflow.batch import BatchRejected


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_MODULES = (
    ROOT / "backend" / "src" / "workflow" / "asi01_batch.py",
    ROOT / "backend" / "src" / "workflow" / "dispatch.py",
    ROOT / "backend" / "src" / "workflow" / "generic_imported_batch.py",
    ROOT / "backend" / "src" / "workflow" / "offline_batch.py",
    ROOT / "backend" / "src" / "workflow" / "toolbot_lab_batch.py",
    ROOT / "backend" / "src" / "workflow" / "web_live_batch.py",
    ROOT / "backend" / "src" / "workflow" / "web_mock_batch.py",
)


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def _target_profile() -> TargetProfile:
    return TargetProfile.model_validate({
        "id": "demo-target",
        "name": "Demo",
        "target_type": "agent",
        "interface": {
            "type": "http",
            "adapter": "generic_http",
            "config": {"endpoint": "http://127.0.0.1:7001/v1/chat/completions"},
        },
    })


def test_stage1a_workflows_do_not_import_run_native_smoke():
    for module_path in WORKFLOW_MODULES:
        imported = _imports(module_path)
        assert "backend.scripts.run_native_smoke" not in imported, str(module_path)
        assert "testing.report_builder" in imported, str(module_path)


def test_web_live_batch_depends_on_web_lab_assets_not_web_mock_batch():
    imported = _imports(ROOT / "backend" / "src" / "workflow" / "web_live_batch.py")
    assert "workflow.web_lab_assets" in imported
    assert "workflow.web_mock_batch" not in imported


def test_report_builder_and_run_native_smoke_aliases_match():
    assert run_native_smoke.RecordingExecutor is report_builder.RecordingExecutor
    assert run_native_smoke.build_summary is report_builder.build_summary
    assert run_native_smoke.build_test_input is report_builder.build_test_input
    assert run_native_smoke.safe_identifier is report_builder.safe_identifier
    assert run_native_smoke.SAFE_IDENTIFIER == report_builder.SAFE_IDENTIFIER


def test_report_builder_summary_and_identifier_contracts():
    target = _target_profile()
    case = TestCaseLoader().load(ROOT / "testcases" / "goal_hijacking" / "GH-001.yaml")
    evaluation = EvaluationResult(status=EvaluationStatus.PASS, reason="Deterministic check passed.")
    execution = ExecutionResult(success=True, status_code=200)
    stamp = datetime(2026, 11, 21, 12, 30, tzinfo=timezone.utc)

    summary = report_builder.build_summary(case, target, evaluation, execution, stamp)
    assert summary == {
        "engine": "native",
        "timestamp": "2026-11-21T12:30:00Z",
        "testcase_id": "GH-001",
        "category": "goal_hijacking",
        "attack_module": "goal_hijacking",
        "target_id": "demo-target",
        "adapter": "generic_http",
        "smoke_execution_succeeded": True,
        "evaluation_status": "PASS",
        "black_box_evidence_semantics": {
            "scope": "black_box",
            "observes": "Adapter-visible response or direct MCP result only.",
            "limitation": "No internal agent trace or private target context is observed.",
        },
    }

    with pytest.raises(ValueError, match="simple testcase and target identifiers"):
        report_builder.safe_identifier("../escape")


def test_recording_executor_captures_last_result_and_handles_fixture_fault():
    class _StubExecutor(Executor):
        def execute(self, target, test_input):
            return ExecutionResult(success=True, status_code=200, events=[])

    class _BrokenFixture:
        def claim(self):
            return None

        def evidence(self, started, ended):
            raise ValueError("fixture unavailable")

    target = _target_profile()
    executor = report_builder.RecordingExecutor(_StubExecutor(), _BrokenFixture())
    result = executor.execute(target, NativeTestInput(id="input-1", prompt="hello", payload_ref="GH-P001"))
    assert executor.last_result is result
    assert result.events[-1]["kind"] == "collector_diagnostic"
    assert result.events[-1]["data"]["observation_complete"] is False


def test_web_lab_assets_preserved_and_aliased(tmp_path):
    assert web_mock_batch.WEB_ATTACK == web_lab_assets.WEB_ATTACK == "GH-WEB-001"
    assert web_mock_batch.WEB_CONTROL == web_lab_assets.WEB_CONTROL == "GH-WEB-C01"
    assert web_mock_batch.REVIEWED_HASHES == web_lab_assets.REVIEWED_HASHES
    assert web_mock_batch.WebAssets is web_lab_assets.WebAssets
    assert web_mock_batch.load_web_assets is web_lab_assets.load_web_assets
    assert web_mock_batch._input is web_lab_assets._input

    assets = web_lab_assets.load_web_assets(ROOT)
    bound_input = web_lab_assets._input(
        assets.control.model_copy(update={"variables": {"page_url": "http://127.0.0.1:9999/page/control/" + "a" * 32}}),
        assets.payloads,
        "exec1",
    )
    assert bound_input.id == "web-batch-exec1"
    assert bound_input.payload_ref == "GH-PWEB-C01"

    with pytest.raises(BatchRejected, match="not fully bound"):
        web_lab_assets._input(
            assets.control.model_copy(update={"variables": {"page_url": "http://127.0.0.1:9999/unconfigured"}}),
            assets.payloads,
            "exec2",
        )

    with pytest.raises(FileNotFoundError):
        web_lab_assets.load_web_assets(tmp_path)


def test_clean_subprocess_import_has_no_circular_import_or_side_effect(tmp_path):
    # Pure src-only PYTHONPATH works for extracted canonical modules without backend.scripts.
    src_only = subprocess.run(
        [
            sys.executable,
            "-c",
            "import testing.report_builder, workflow.web_lab_assets",
        ],
        cwd=tmp_path,
        env={"PYTHONPATH": str(ROOT / "backend" / "src")},
        capture_output=True,
        text=True,
        check=False,
    )
    assert src_only.returncode == 0, src_only.stderr
    assert src_only.stdout == ""

    # Standard repo PYTHONPATH loads full workflows and API without circular imports or stdout side effects.
    repo_proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "import testing.report_builder, workflow.web_lab_assets, workflow.web_live_batch, workflow.web_mock_batch, workflow.dispatch, workflow.api",
        ],
        cwd=tmp_path,
        env={"PYTHONPATH": os.pathsep.join([str(ROOT / "backend" / "src"), str(ROOT)])},
        capture_output=True,
        text=True,
        check=False,
    )
    assert repo_proc.returncode == 0, repo_proc.stderr
    assert repo_proc.stdout == ""
    assert not (tmp_path / "results").exists()
