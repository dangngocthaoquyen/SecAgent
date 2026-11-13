"""Bounded explicit dataset selection and opt-in controlled-run lookup."""
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
from typing import Literal

from pydantic import Field

from reporting.aggregation import AggregationSummary, aggregate_reports
from reporting.artifacts import ArchiveReader, MAX_ARTIFACT_BYTES, _json, verify_archive
from reporting.models import ArchivedAssessmentReport, ExecutionReport, Model
from reporting.normalizers import normalize_report_bytes

MAX_INPUTS = 128
MAX_DATASET_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024


class DatasetError(ValueError):
    """Public message never includes paths or source contents."""


class SelectedReport(Model):
    root: str = Field(min_length=1, max_length=64)
    path: str = Field(min_length=1, max_length=4096)
    kind: Literal["execution", "archived_assessment"]


class VerificationJob(Model):
    root: str = Field(min_length=1, max_length=64)
    inventory: str = Field(min_length=1, max_length=4096)
    execution: str = Field(min_length=1, max_length=4096)
    assessment: str | None = Field(default=None, min_length=1, max_length=4096)


class DatasetManifest(Model):
    dataset_schema_version: Literal["1.0.0"]
    allowed_roots: dict[str, str] = Field(max_length=8)
    reports: list[SelectedReport] = Field(default_factory=list, max_length=MAX_INPUTS)
    verification_jobs: list[VerificationJob] = Field(default_factory=list, max_length=16)
    controlled_runs_root: str | None = None


@dataclass(frozen=True)
class ReportDataset:
    records: tuple[ExecutionReport | ArchivedAssessmentReport, ...]
    summary: AggregationSummary
    current_verification_sources: frozenset[str]
    controlled_runs_root: Path | None = None


def load_controlled_run(dataset: ReportDataset, run_id: str) -> ExecutionReport:
    """Resolve one backend-issued run under an explicitly selected local root."""
    if dataset.controlled_runs_root is None or not re.fullmatch(r"[a-f0-9]{32}", run_id):
        raise DatasetError("Controlled run is unavailable.")
    try:
        reader = _local_root(dataset.controlled_runs_root)
        raw_summary = reader.read(reader.path(f"{run_id}/run-summary.json"), MAX_MANIFEST_BYTES)
        if raw_summary is None:
            raise ValueError()
        summary = _json(raw_summary)
        filename = summary.get("report_file")
        digest = summary.get("report_sha256")
        if (summary.get("run_id") != run_id or summary.get("report_persisted") is not True
                or not isinstance(filename, str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,256}\.secagent\.json", filename)
                or not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest)):
            raise ValueError()
        raw_report = reader.read(reader.path(f"{run_id}/{filename}"))
        if raw_report is None or hashlib.sha256(raw_report).hexdigest() != digest:
            raise ValueError()
        source = _json(raw_report)
        if not isinstance(source, dict):
            raise ValueError()
        evaluation = source.get("evaluation")
        if (not isinstance(evaluation, dict)
                or evaluation.get("run_id") != summary.get("native_execution_id")
                or source.get("testcase_id") != summary.get("testcase_id")
                or source.get("target_id") != summary.get("target_id")):
            raise ValueError()
        record = normalize_report_bytes(raw_report)
        if record.report_kind != "execution" or record.source.file_byte_sha256 != digest:
            raise ValueError()
        return record
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        raise DatasetError("Controlled run is invalid or unavailable.") from None


def _local_root(path):
    if str(path).startswith(("\\\\", "//")):
        raise DatasetError("Network datasets are unsupported.")
    # Reject mapped network drives too, before accessing file metadata on Windows.
    if os.name == "nt":
        import ctypes
        if ctypes.windll.kernel32.GetDriveTypeW(str(Path(path).anchor)) == 4:
            raise DatasetError("Network datasets are unsupported.")
    return ArchiveReader(path)


def load_dataset(manifest_path) -> ReportDataset:
    """Reject the whole selection on error. No scan, writer, remote fetch or lazy request-time IO."""
    try:
        manifest_path = Path(manifest_path).absolute()
        manifest_reader = _local_root(manifest_path.parent)
        raw = manifest_reader.read(manifest_reader.path(manifest_path.name), MAX_MANIFEST_BYTES)
        if raw is None:
            raise ValueError()
        manifest = DatasetManifest.model_validate(_json(raw))
        if len(manifest.reports) + sum(1 + (j.assessment is not None) for j in manifest.verification_jobs) > MAX_INPUTS:
            raise ValueError()
        readers = {}
        for name, root in manifest.allowed_roots.items():
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", name) or not isinstance(root, str) or not root or len(root) > 4096:
                raise ValueError()
            # Root declarations are operator-controlled and relative to the manifest.
            # abspath removes lexical '..' without following symlinks; ArchiveReader rejects links.
            root = os.path.abspath(manifest_path.parent / root)
            readers[name] = _local_root(root)
        cache = {}
        total = 0

        def read(root_name, relative, limit=MAX_ARTIFACT_BYTES):
            nonlocal total
            reader = readers[root_name]
            path = reader.path(relative)
            if path not in cache:
                content = reader.read(path, limit)
                if content is None:
                    raise ValueError()
                total += len(content)
                if total > MAX_DATASET_BYTES:
                    raise ValueError()
                cache[path] = content
            if len(cache[path]) > limit:
                raise ValueError()
            return path, cache[path]

        records = []
        computed = set()
        for selection in manifest.reports:
            _, content = read(selection.root, selection.path)
            record = normalize_report_bytes(content)
            if record.report_kind != selection.kind:
                raise ValueError()
            records.append(record)
        for job in manifest.verification_jobs:
            _, inventory = read(job.root, job.inventory, MAX_MANIFEST_BYTES)
            base = Path(job.inventory).parent
            selected = {"manifest": str(base / "fixture/manifest.json"), "events": str(base / "fixture/events.jsonl"),
                        "collector_export": str(base / "sanitized-collector-after.json"), "execution": job.execution}
            if job.assessment:
                selected["assessment"] = job.assessment
            digests = {role: hashlib.sha256(read(job.root, path)[1]).hexdigest() for role, path in selected.items()}
            digests["inventory"] = hashlib.sha256(inventory).hexdigest()
            bundle = verify_archive(readers[job.root].root, inventory=job.inventory, execution=job.execution, assessment=job.assessment)
            if any(c.actual_file_byte_sha256 != digests.get(c.artifact_role) for c in bundle.verification.artifacts):
                raise ValueError()  # Files changed between bounded selection and verification.
            if bundle.execution is None or (job.assessment and bundle.assessment is None):
                raise ValueError()
            for record in (bundle.execution, bundle.assessment):
                if record:
                    records.append(record)
                    computed.add(record.source.file_byte_sha256)
        summary = aggregate_reports(records)  # Preserves duplicate/conflicting projection policy.
        unique = {(r.report_kind, r.source.file_byte_sha256): r for r in records}
        if manifest.controlled_runs_root is not None and manifest.controlled_runs_root not in readers:
            raise ValueError()
        run_root = readers[manifest.controlled_runs_root].root if manifest.controlled_runs_root else None
        return ReportDataset(tuple(unique[k] for k in sorted(unique)), summary, frozenset(computed), run_root)
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        raise DatasetError("Dataset selection is invalid, unsafe, oversized or unavailable.") from None
