"""Trusted batch orchestration over server-owned case executors.

This module has no live target binding. Its caller supplies server-owned
admission and a bounded native Runner executor.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
import re
from pathlib import Path
from threading import Event, Lock, Thread
from time import sleep
from uuid import uuid4
from typing import Any, Callable, Literal


CaseStatus = Literal["completed", "error", "blocked", "unsupported", "skipped", "cancelled"]
Verdict = Literal["PASS", "FAIL", "INCONCLUSIVE", "ERROR"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _owner_alive(marker: dict) -> bool:
    pid = marker.get("pid")
    if not isinstance(pid, int) or pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = (ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong)
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.GetExitCodeProcess.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong))
        kernel.CloseHandle.argtypes = (ctypes.c_void_p,)
        handle = kernel.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False if ctypes.get_last_error() == 87 else True
        try:
            code = ctypes.c_ulong()
            return not kernel.GetExitCodeProcess(handle, ctypes.byref(code)) or code.value == 259
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except (PermissionError, OSError):
        return True  # Uncertain ownership must fail closed.


def _write_atomic(path: Path, value: dict) -> None:
    temporary = path.with_name("." + path.name + "." + uuid4().hex + ".tmp")
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        for attempt in range(20):
            try:
                os.replace(temporary, path)
                break
            except PermissionError:
                if attempt == 19:
                    raise
                sleep(0.01)  # Windows readers briefly deny replacement.
    finally:
        temporary.unlink(missing_ok=True)


def write_exclusive_json(path: Path, payload: Any) -> None:
    """Create a new UTF-8 JSON file exclusively and flush + fsync it to disk."""

    with path.open("x", encoding="utf-8") as stream:
        json.dump(payload, stream)
        stream.flush()
        os.fsync(stream.fileno())


def _write_exclusive_sorted_json(path: Path, payload: Any) -> None:
    """Create a new UTF-8 JSON file exclusively with deterministic sorted keys."""

    with path.open("x", encoding="utf-8") as stream:
        json.dump(payload, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())


@dataclass(frozen=True)
class BatchCase:
    testcase_id: str
    name: str
    asi_category: str
    asset_sha256: str
    input_sha256: str
    request_budget: int = 1

    def __post_init__(self):
        if (not self.testcase_id or not self.name or not self.asi_category
                or len(self.testcase_id) > 128 or len(self.name) > 160
                or len(self.asi_category) > 16
                or any(len(value) != 64 or any(c not in "0123456789abcdef" for c in value)
                       for value in (self.asset_sha256, self.input_sha256))
                or self.request_budget < 0):
            raise ValueError("Invalid batch case snapshot.")


@dataclass(frozen=True)
class BatchPlan:
    target_id: str
    profile_revision: str
    policy_ref: str
    evaluation_mode: Literal["rule_only", "hybrid"]
    cases: tuple[BatchCase, ...]
    total_request_budget: int
    imported_provenance: dict | None = None

    def __post_init__(self):
        if (not self.target_id or not self.policy_ref
                or len(self.profile_revision) != 64
                or any(c not in "0123456789abcdef" for c in self.profile_revision)
                or not self.cases or self.total_request_budget < 0
                or len({case.testcase_id for case in self.cases}) != len(self.cases)):
            raise ValueError("Invalid or duplicate batch selection.")

    def snapshot(self) -> dict:
        snapshot = {"target_id": self.target_id, "profile_revision": self.profile_revision,
                "policy_ref": self.policy_ref, "evaluation_mode": self.evaluation_mode,
                "total_request_budget": self.total_request_budget,
                "cases": [case.__dict__.copy() for case in self.cases]}
        if self.imported_provenance is not None:
            snapshot["imported_provenance"] = self.imported_provenance
        return snapshot


@dataclass(frozen=True)
class CaseResult:
    """Trusted executor result. Report persistence remains with the native Runner."""

    execution_status: Literal["completed", "error", "blocked", "cancelled"]
    verdict: Verdict | None
    request_count: int
    report_run_id: str | None = None
    report_sha256: str | None = None
    response_captured: bool | None = None
    response_complete: bool | None = None
    evidence_provenance: str | None = None
    reason: str | None = None
    preflight_id: str | None = None
    evaluation_reason: str | None = None

    def __post_init__(self):
        if (self.request_count < 0 or
                (self.execution_status == "error" and self.verdict != "ERROR") or
                (self.execution_status == "completed" and (self.verdict is None or self.verdict == "ERROR")) or
                (self.execution_status in {"blocked", "cancelled"}
                    and (self.verdict is not None or self.report_run_id is not None)) or
                (self.reason is not None and (not re.fullmatch(r"[a-z_]{1,80}", self.reason)
                    or self.execution_status not in {"blocked", "cancelled"})) or
                (self.preflight_id is not None and not re.fullmatch(r"[a-f0-9]{32}", self.preflight_id)) or
                (self.evaluation_reason is not None and (len(self.evaluation_reason) > 240
                    or any(ord(char) < 32 or ord(char) == 127 for char in self.evaluation_reason))) or
                ((self.report_run_id is None) != (self.report_sha256 is None)) or
                (self.execution_status == "completed" and self.report_run_id is None) or
                (self.report_run_id is not None and
                 (len(self.report_run_id) != 32 or any(c not in "0123456789abcdef" for c in self.report_run_id))) or
                (self.report_sha256 is not None and
                 (len(self.report_sha256) != 64 or any(c not in "0123456789abcdef" for c in self.report_sha256)))):
            raise ValueError("Invalid case execution result.")


class BatchRejected(ValueError):
    pass


def evaluation_reason_from_summary(summary: dict) -> str | None:
    """Use only the already-sanitized native final reason in progress records."""
    reason = ((summary.get("evaluation") or {}).get("final_result") or {}).get("reason")
    if (not isinstance(reason, str) or len(reason) > 240
            or any(ord(char) < 32 or ord(char) == 127 for char in reason)):
        return None
    return reason


def persist_batch_case_report(
    run_dir: Path,
    *,
    run_id: str,
    testcase_id: str,
    target_id: str,
    summary: dict[str, Any],
    verdict: Verdict,
    request_count: int,
    response_captured: bool,
    response_complete: bool | None,
    artifact_provenance: str,
    batch_execution_id: str,
    input_sha256: str,
    asset_sha256: str,
    preflight_id: str | None = None,
    extra_summary_fields: dict[str, Any] | None = None,
) -> CaseResult:
    """Persist native report, SHA256 digest, and run-summary.json, returning CaseResult."""

    filename = f"native-{testcase_id}-{run_id}.secagent.json"
    report = run_dir / filename
    _write_exclusive_sorted_json(report, summary)
    report_hash = sha256(report.read_bytes()).hexdigest()
    summary_row: dict[str, Any] = {
        "workflow_schema_version": "1.0.0",
        "run_id": run_id,
        "native_execution_id": summary["evaluation"].get("run_id"),
        "testcase_id": testcase_id,
        "target_id": target_id,
        "execution_status": "failed" if verdict == "ERROR" else "completed",
        "historical_verdict": verdict,
        "target_request_count": request_count,
        "report_persisted": True,
        "report_file": filename,
        "report_sha256": report_hash,
        "response_captured": response_captured,
        "response_complete": response_complete,
        "artifact_provenance": artifact_provenance,
        "batch_execution_id": batch_execution_id,
        "input_sha256": input_sha256,
        "asset_sha256": asset_sha256,
    }
    if preflight_id is not None:
        summary_row["preflight_id"] = preflight_id
    if extra_summary_fields:
        summary_row.update(extra_summary_fields)
    _write_exclusive_sorted_json(run_dir / "run-summary.json", summary_row)
    return CaseResult(
        "error" if verdict == "ERROR" else "completed",
        verdict,
        request_count,
        run_id,
        report_hash,
        response_captured,
        response_complete,
        artifact_provenance,
        preflight_id=preflight_id,
        evaluation_reason=evaluation_reason_from_summary(summary),
    )


class BatchOrchestrator:
    """Sequential durable state and claims; never dispatches a target itself."""

    def __init__(self, root: Path):
        self.root = Path(root).absolute()
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self._active = False
        marker = self.root / ".active-batch"
        if marker.exists():
            try:
                owner = json.loads(marker.read_text(encoding="utf-8"))
                identity = owner["batch_run_id"]
                if not isinstance(identity, str) or len(identity) != 32 or any(
                        c not in "0123456789abcdef" for c in identity):
                    raise ValueError("Invalid batch claim identity.")
                if not _owner_alive(owner):
                    path = self.root / identity / "state.json"
                    state = json.loads(path.read_text(encoding="utf-8"))
                    if state.get("status") in {"preparing", "running"}:
                        state["status"] = "interrupted"
                        state["active_testcase_id"] = None
                        state["events"].append({"at": _now(), "stage": "interrupted",
                                                "testcase_id": None})
                        _write_atomic(path, state)
                    marker.unlink()
            except (OSError, ValueError, KeyError, TypeError):
                pass  # Unknown claim remains fail closed for operator review.

    def state(self, batch_run_id: str) -> dict:
        if len(batch_run_id) != 32 or any(c not in "0123456789abcdef" for c in batch_run_id):
            raise BatchRejected("Invalid batch run ID.")
        path = self.root / batch_run_id / "state.json"
        for attempt in range(20):
            try:
                state = json.loads(path.read_text(encoding="utf-8"))
                if state.get("snapshot", {}).get("imported_provenance") is not None:
                    self._verify_imported_state(state, path.parent)
                if state.get("status") in {"preparing", "running"}:
                    marker = self.root / ".active-batch"
                    try:
                        owner = json.loads(marker.read_text(encoding="utf-8"))
                    except (OSError, ValueError):
                        owner = {}
                    if owner.get("batch_run_id") != batch_run_id or not _owner_alive(owner):
                        state["status"] = "interrupted"
                return state
            except PermissionError:
                if attempt == 19:
                    raise BatchRejected("Unknown or invalid batch run.") from None
                sleep(0.01)
            except (OSError, ValueError):
                raise BatchRejected("Unknown or invalid batch run.") from None

    def _verify_imported_state(self, state: dict, directory: Path) -> None:
        """Check new imported batches without changing historical batch contracts."""
        from reporting.artifacts import ArchiveReader
        snapshot_hash = sha256(json.dumps(state["snapshot"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if snapshot_hash != state.get("snapshot_sha256"):
            raise BatchRejected("Imported batch snapshot integrity mismatch.")
        reader = ArchiveReader(self.root.parent)
        for row in state["results"]:
            run_id = row.get("report_run_id")
            if run_id is None:
                continue
            if not re.fullmatch(r"[a-f0-9]{32}", run_id):
                raise BatchRejected("Invalid native report identity.")
            raw_summary = reader.read(reader.path(f"{run_id}/run-summary.json"))
            summary = json.loads(raw_summary or b'{}')
            filename = summary.get("report_file", "")
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,256}\.secagent\.json", filename):
                raise BatchRejected("Invalid native report reference.")
            raw_report = reader.read(reader.path(f"{run_id}/{filename}"))
            if raw_report is None or sha256(raw_report).hexdigest() != row.get("report_sha256"):
                raise BatchRejected("Native report integrity mismatch.")
            report = json.loads(raw_report)
            if (report.get("runtime_snapshot", {}).get("target_request_count") != row.get("request_count")
                    or summary.get("target_request_count") != row.get("request_count")
                    or summary.get("report_sha256") != row.get("report_sha256")):
                raise BatchRejected("Imported request count integrity mismatch.")
        if state.get("aggregate_report_sha256"):
            raw = reader.read(reader.path(str((directory / "batch-report.json").relative_to(self.root.parent))))
            if raw is None or sha256(raw).hexdigest() != state['aggregate_report_sha256']:
                raise BatchRejected("Aggregate report integrity mismatch.")
            aggregate = json.loads(raw)
            for key in ("target_request_count", "request_budget_consumed", "request_count_unknown", "status"):
                if aggregate.get(key) != state.get(key):
                    raise BatchRejected("Aggregate result mismatch.")
            if len(aggregate['cases']) != len(state['results']):
                raise BatchRejected("Aggregate case count mismatch.")
            for actual, stored in zip(state['results'], aggregate['cases']):
                if any(actual.get(key) != value for key, value in stored.items()):
                    raise BatchRejected("Aggregate case result mismatch.")

    def cancel_remaining(self, batch_run_id: str) -> dict:
        state = self.state(batch_run_id)
        if state["status"] in {"completed", "partially_completed", "cancelled", "failed", "interrupted"}:
            return state
        marker = self.root / batch_run_id / "cancel-requested.json"
        try:
            with marker.open("x", encoding="utf-8") as stream:
                json.dump({"requested_at": _now(), "active_testcase_id": state["active_testcase_id"]}, stream)
                stream.flush()
                os.fsync(stream.fileno())
        except FileExistsError:
            pass
        return self.state(batch_run_id)

    def cancellation_requested(self) -> bool:
        """Fail closed before a second request in an active trusted case executor."""
        try:
            owner = json.loads((self.root / ".active-batch").read_text(encoding="utf-8"))
            identity = owner["batch_run_id"]
            if (owner.get("pid") != os.getpid() or not isinstance(identity, str)
                    or not re.fullmatch(r"[a-f0-9]{32}", identity)):
                return True
            return (self.root / identity / "cancel-requested.json").exists()
        except (OSError, ValueError, KeyError, TypeError):
            return True

    def run(self, plan: BatchPlan,
            admit: Callable[[BatchCase], Literal["ready", "blocked", "unsupported", "skipped"]],
            execute: Callable[[BatchCase, str, Callable[[str], None]], CaseResult],
            *, batch_run_id: str | None = None,
            on_started: Callable[[], None] | None = None) -> dict:
        """Only trusted code may supply admission and execution callbacks.

        `execute` must enforce its own per-case transport cap. The returned
        request count is checked here; transport reservations cannot be undone.
        """
        if not self._lock.acquire(blocking=False):
            raise BatchRejected("Another batch operation is active.")
        try:
            if self._active:
                raise BatchRejected("Another batch is active.")
            self._active = True
            identity = batch_run_id or uuid4().hex
            if len(identity) != 32 or any(c not in "0123456789abcdef" for c in identity):
                raise BatchRejected("Invalid batch run ID.")
            active_claim = self.root / ".active-batch"
            claimed_active = False
            try:
                with active_claim.open("x", encoding="utf-8") as stream:
                    json.dump({"batch_run_id": identity, "claimed_at": _now(), "pid": os.getpid()}, stream)
                    stream.flush()
                    os.fsync(stream.fileno())
                claimed_active = True
            except FileExistsError:
                raise BatchRejected("Another batch is active or needs recovery.") from None
            directory = self.root / identity
            try:
                directory.mkdir(exist_ok=False)  # Durable, exclusive batch claim.
            except FileExistsError:
                raise BatchRejected("Batch run was already claimed.") from None
            snapshot = plan.snapshot()
            snapshot_hash = sha256(json.dumps(snapshot, sort_keys=True,
                separators=(",", ":")).encode()).hexdigest()
            state = {"schema_version": "1.0.0", "batch_run_id": identity,
                "snapshot": snapshot, "snapshot_sha256": snapshot_hash,
                "status": "preparing", "total": len(plan.cases), "processed": 0,
                "target_request_count": 0, "request_budget_consumed": 0,
                "request_count_unknown": False, "active_testcase_id": None,
                "results": [], "events": [], "created_at": _now()}

            def persist(stage: str, case_id: str | None = None):
                state["events"].append({"at": _now(), "stage": stage, "testcase_id": case_id})
                _write_atomic(directory / "state.json", state)

            persist("preparing")
            if on_started is not None:
                on_started()
            try:
              for case in plan.cases:
                if (directory / "cancel-requested.json").exists():
                    state["status"] = "cancelled"
                    break
                execution_id = uuid4().hex
                state["status"] = "running"
                state["active_testcase_id"] = case.testcase_id
                persist("validating_testcase", case.testcase_id)
                try:
                    admission = admit(case)
                    outcome, reason = admission if isinstance(admission, tuple) and len(admission) == 2 else (admission, None)
                except Exception:
                    outcome = "blocked"
                    reason = None
                    admission_fault = True
                else:
                    admission_fault = False
                if outcome not in {"ready", "blocked", "unsupported", "skipped"}:
                    outcome, admission_fault = "blocked", True
                if reason is not None and (not isinstance(reason, str) or
                        not re.fullmatch(r"[a-z_]{1,80}", reason)):
                    outcome, reason, admission_fault = "blocked", None, True
                row = {"testcase_id": case.testcase_id, "execution_id": execution_id,
                       "status": outcome, "verdict": None, "request_count": 0,
                       "report_run_id": None, "report_sha256": None,
                       "response_captured": None, "response_complete": None,
                       "evidence_provenance": None, "preflight_id": None}
                if admission_fault:
                    row["reason"] = "admission_fault"
                elif reason:
                    row["reason"] = reason
                if outcome == "ready":
                    if state["request_budget_consumed"] + case.request_budget > plan.total_request_budget:
                        row["status"] = "blocked"
                        row["reason"] = "batch_request_budget_exhausted"
                    else:
                        persist("preparing_execution", case.testcase_id)

                        def stage(value: str):
                            if value not in {"sending_target_request", "waiting_for_target_response",
                                    "collecting_evidence", "running_rule_evaluator",
                                    "invoking_pi_judge", "resolving_verdict", "saving_report",
                                    "preparing_web_fixture", "verifying_web_capability"}:
                                raise ValueError("Unsupported progress stage.")
                            persist(value, case.testcase_id)

                        try:
                            result = execute(case, execution_id, stage)
                            if result.request_count > case.request_budget:
                                raise BatchRejected("Case executor exceeded reserved request budget.")
                            if (result.report_run_id is not None and any(
                                    prior["report_run_id"] == result.report_run_id
                                    for prior in state["results"])):
                                raise BatchRejected("A native report was reused across cases.")
                            row.update(status=result.execution_status, verdict=result.verdict,
                                request_count=result.request_count, report_run_id=result.report_run_id,
                                report_sha256=result.report_sha256,
                                response_captured=result.response_captured,
                                response_complete=result.response_complete,
                                evidence_provenance=result.evidence_provenance,
                                preflight_id=result.preflight_id,
                                evaluation_reason=result.evaluation_reason)
                            if result.reason:
                                row["reason"] = result.reason
                            state["target_request_count"] += result.request_count
                            state["request_budget_consumed"] += result.request_count
                        except Exception:
                            # A transport attempt may have happened before a callback fault.
                            # Consume the full budget, while leaving actual count unknown.
                            row.update(status="error", verdict="ERROR", request_count=None,
                                       reason="execution_or_accounting_fault")
                            state["request_budget_consumed"] += case.request_budget
                            state["request_count_unknown"] = True
                state["results"].append(row)
                state["processed"] += 1
                state["active_testcase_id"] = None
                persist("case_recorded", case.testcase_id)
              else:
                states = {item["status"] for item in state["results"]}
                state["status"] = ("cancelled" if "cancelled" in states and
                                   (directory / "cancel-requested.json").exists() else
                                   "completed" if states == {"completed"} else
                                   "failed" if states == {"error"} else "partially_completed")
            except Exception:
                state["status"] = "failed"
                persist("orchestration_fault")
            if state["status"] == "cancelled":
                recorded = {item["testcase_id"] for item in state["results"]}
                for case in plan.cases:
                    if case.testcase_id not in recorded:
                        state["results"].append({"testcase_id": case.testcase_id,
                            "execution_id": None, "status": "cancelled", "verdict": None,
                            "request_count": 0, "report_run_id": None, "report_sha256": None,
                            "response_captured": None, "response_complete": None,
                            "evidence_provenance": None})
            state["active_testcase_id"] = None
            aggregate = {"schema_version": "1.0.0", "batch_run_id": identity,
                "snapshot_sha256": snapshot_hash, "status": state["status"],
                "target_request_count": state["target_request_count"],
                "request_budget_consumed": state["request_budget_consumed"],
                "request_count_unknown": state["request_count_unknown"],
                "selected_cases": len(plan.cases), "processed_cases": state["processed"],
                "cases": [{key: row.get(key) for key in ("testcase_id", "execution_id",
                    "status", "verdict", "request_count", "report_run_id", "report_sha256",
                    "evidence_provenance", "evaluation_reason", "reason")}
                    for row in state["results"]]}
            _write_atomic(directory / "batch-report.json", aggregate)
            state["aggregate_report_sha256"] = sha256((directory / "batch-report.json").read_bytes()).hexdigest()
            persist("terminal")
            return self.state(identity)
        finally:
            if 'claimed_active' in locals() and claimed_active:
                # An interrupted or unrecorded run leaves the claim fail closed.
                if 'state' not in locals() or state.get('status') in {
                        'completed', 'partially_completed', 'cancelled', 'failed'}:
                    active_claim.unlink(missing_ok=True)
            self._active = False
            self._lock.release()


def launch_batch_worker(
    *,
    dispatcher: Any,
    orchestrator: BatchOrchestrator,
    plan: "BatchPlan",
    admit: Callable[["BatchCase"], Any],
    execute: Callable[["BatchCase", str, Callable[[str], None]], CaseResult],
    batch_run_id: str,
    plan_id: str,
    thread_name: str,
    set_worker: Callable[[Thread], None],
    on_cleanup: Callable[[], None] | None = None,
    start_timeout: float = 5.0,
) -> dict[str, Any]:
    """Launch a controlled non-daemon batch worker thread with fail-closed startup recovery."""
    started = Event()

    def release_execution_state() -> None:
        with dispatcher._lock:
            dispatcher._active = False
            if on_cleanup is not None:
                on_cleanup()

    def worker() -> None:
        try:
            orchestrator.run(
                plan,
                admit,
                execute,
                batch_run_id=batch_run_id,
                on_started=started.set,
            )
        finally:
            release_execution_state()
            started.set()

    try:
        thread = Thread(target=worker, name=thread_name, daemon=False)
        set_worker(thread)
        thread.start()
    except BaseException:
        release_execution_state()
        raise

    if not started.wait(start_timeout):
        raise BatchRejected("Batch state did not become available.")

    state = orchestrator.state(batch_run_id)
    return {
        "workflow_schema_version": "1.0.0",
        "batch_run_id": batch_run_id,
        "status": state["status"],
        "plan_id": plan_id,
        "progress_view": f"/api/testing/batches/{batch_run_id}",
    }
