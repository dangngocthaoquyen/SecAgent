"""Phase 1A generic offline stored-response importer and normalizer.

Reusable across OWASP Agentic categories (ASI01, ASI02, ASI03, ASI05) and
arbitrary dataset sizes, with or without historical reference verdicts.

Core design boundaries:
- Target-agnostic, adapter-agnostic, and count-agnostic canonical schema.
- Never calls any target HTTP endpoint, Judge provider, or LLM CLI.
- Strictly isolates Judge-safe blind inputs from external tool verdicts,
  assertions, grading reasons, and untrusted testcase metadata.
- Treats DSML markup strictly as unverified model_reported tool intent
  (execution_verified=False), never equating it with structured tool execution.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Literal, Protocol
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field

from core.models.dsml import DsmlIntentSignal, detect_dsml_intent
from core.models.evidence import Evidence
from core.models.execution import resolve_response_completeness
from testing.archived_crosscheck import ArchiveError, parse_json, read_bytes, sha

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUTPUT_DIR = ROOT / "results/judge-validation/offline-stored-import"
BLIND_DATASET_FILENAME = "blind-evaluation-dataset.json"
HISTORICAL_DATASET_FILENAME = "historical-comparison-dataset.json"

DEFAULT_SECRET_ENV_VARS = (
    "DEEPSEEK_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "SECAGENT_API_KEY",
    "LLM_API_KEY",
    "API_KEY",
)

FORBIDDEN_BLIND_KEYS = frozenset({
    "gradingResult",
    "success",
    "score",
    "failureReason",
    "assert",
    "assertions",
    "componentResults",
    "namedScores",
    "namedScoreWeights",
    "reason",
    "purpose",
    "pluginConfig",
    "modifiers",
    "severity",
    "grading_pass",
    "grading_score",
    "grading_reason",
    "promptfoo_success",
    "promptfoo_score",
    "promptfoo_failure_reason",
    "promptfoo_grading_result",
    "promptfoo_assertions",
    "external_verdict",
    "external_pass",
    "external_score",
    "external_failure_reason",
    "external_grading_result",
    "external_assertions",
    "verdict",
    "final_verdict",
})

_SECRET_REGEXES = (
    (re.compile(r"\bsk-[A-Za-z0-9_-]{8,}"), "[REDACTED_KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{12,}"), "[REDACTED_TOKEN]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "[REDACTED_JWT]"),
    (re.compile(r"(?i)\bBearer\s+[^\s\"<>]{6,}"), "Bearer [REDACTED]"),
)


class BlindStoredEvidence(BaseModel):
    """Judge-safe stored observation item without any pass/fail status key."""

    model_config = ConfigDict(extra="forbid")

    kind: str
    source: str
    name: str
    provenance: Literal["target_reported", "model_reported"]
    execution_verified: Literal[False] = False
    data: dict[str, Any] = Field(default_factory=dict)
    reference: str | None = None

    def to_core_evidence(self) -> Evidence:
        """Convert to SecAgent core Evidence with success=None (no implied verdict)."""
        return Evidence(
            kind=self.kind,
            source=self.source,
            name=self.name,
            success=None,
            data={
                **self.data,
                "provenance": self.provenance,
                "execution_verified": self.execution_verified,
            },
            reference=self.reference,
        )


class StoredRecordProvenance(BaseModel):
    """Explicit offline import provenance for a stored target response."""

    model_config = ConfigDict(extra="forbid")

    adapter_name: str
    target_id: str | None = None
    target_port: int | None = None
    provider_label: str | None = None
    source_tool: str
    source_filename: str
    source_file_sha256: str
    source_eval_id: str | None = None
    source_timestamp: str | None = None
    source_index: int
    prompt_sha256: str
    response_sha256: str
    direct_target_execution: Literal[False] = False
    judge_evaluated: Literal[False] = False
    execution_verified: Literal[False] = False


class BlindEvaluationRecord(BaseModel):
    """Single canonical blind Judge input record with zero external verdict leakage."""

    model_config = ConfigDict(extra="forbid")

    case_id: str
    category: str | None = None
    plugin_id: str | None = None
    prompt: str
    stored_response: str
    finish_reason: str | None = None
    response_complete: bool | None = None
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    target_metadata: dict[str, Any] = Field(default_factory=dict)
    dsml_signals: DsmlIntentSignal
    response_id: str | None = None
    target_model: str | None = None
    evidence: list[BlindStoredEvidence] = Field(default_factory=list)
    provenance: StoredRecordProvenance


class BlindDatasetSummary(BaseModel):
    """Aggregate statistics for the canonical blind dataset export."""

    model_config = ConfigDict(extra="forbid")

    total_cases: int
    category_counts: dict[str, int]
    plugin_counts: dict[str, int]
    dsml_detected_count: int
    structured_tool_calls_count: int
    target_metadata_present_count: int
    complete_response_count: int


class BlindEvaluationDataset(BaseModel):
    """Generic Phase 1A Blind Evaluation Dataset ready for downstream evaluation prep."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["secagent.offline_blind.v1"] = "secagent.offline_blind.v1"
    phase: Literal["1A"] = "1A"
    category: str | None = None
    source_adapter: str
    imported_at: str
    judge_evaluated: Literal[False] = False
    direct_target_execution: Literal[False] = False
    summary: BlindDatasetSummary
    records: list[BlindEvaluationRecord]


class HistoricalComparisonRecord(BaseModel):
    """External tool verdict/rubric record isolated from Judge input, keyed by case_id."""

    model_config = ConfigDict(extra="forbid")

    case_id: str
    source_index: int
    category: str | None = None
    plugin_id: str | None = None
    external_tool: str
    external_pass: bool | None = None
    external_score: float | int | None = None
    external_failure_reason: int | str | None = None
    external_named_scores: dict[str, Any] = Field(default_factory=dict)
    external_grading_result: dict[str, Any] = Field(default_factory=dict)
    external_assertions: list[dict[str, Any]] = Field(default_factory=list)
    external_untrusted_metadata: dict[str, Any] = Field(default_factory=dict)


class HistoricalDatasetSummary(BaseModel):
    """Aggregate statistics for optional historical comparison outcomes."""

    model_config = ConfigDict(extra="forbid")

    total_cases: int
    verdict_pass_count: int
    verdict_fail_count: int
    category_counts: dict[str, int]
    plugin_counts: dict[str, int]


class HistoricalComparisonDataset(BaseModel):
    """Optional Phase 1A Historical Comparison Dataset for post-Judge calibration."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["secagent.offline_historical.v1"] = "secagent.offline_historical.v1"
    phase: Literal["1A"] = "1A"
    category: str | None = None
    source_adapter: str
    imported_at: str
    source_filename: str
    source_file_sha256: str
    source_eval_id: str | None = None
    has_historical_verdicts: bool
    summary: HistoricalDatasetSummary
    records: list[HistoricalComparisonRecord]


class OfflineImportResult(BaseModel):
    """Return value and JSON-safe CLI summary for Phase 1A offline import."""

    model_config = ConfigDict(extra="forbid")

    adapter_name: str
    category: str | None = None
    blind_dataset_path: str
    historical_dataset_path: str | None = None
    has_historical_verdicts: bool
    total_cases: int
    dsml_detected_count: int
    structured_tool_calls_count: int
    target_metadata_present_count: int
    verdict_pass_count: int
    verdict_fail_count: int
    blind_leakage_check_passed: bool
    source_file_sha256: str


class ImportContext(BaseModel):
    """Caller-supplied provenance defaults without target/category hardcoding."""

    model_config = ConfigDict(extra="forbid")

    source_filename: str
    category: str | None = None
    target_id: str | None = None
    target_port: int | None = None


class RawExternalVerdict(BaseModel):
    """Adapter-extracted historical verdict payload kept outside blind records."""

    model_config = ConfigDict(extra="forbid")

    external_tool: str
    external_pass: bool | None = None
    external_score: float | int | None = None
    external_failure_reason: int | str | None = None
    external_named_scores: dict[str, Any] = Field(default_factory=dict)
    external_grading_result: dict[str, Any] = Field(default_factory=dict)
    external_assertions: list[dict[str, Any]] = Field(default_factory=list)
    external_untrusted_metadata: dict[str, Any] = Field(default_factory=dict)


class RawAdaptedRecord(BaseModel):
    """Normalized intermediate output produced by any source adapter."""

    model_config = ConfigDict(extra="forbid")

    case_id: str | None = None
    source_index: int
    category: str | None = None
    plugin_id: str | None = None
    prompt: str
    stored_response: str
    finish_reason: str | None = None
    response_complete: bool | None = None
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    target_metadata: dict[str, Any] = Field(default_factory=dict)
    response_id: str | None = None
    target_id: str | None = None
    target_port: int | None = None
    target_model: str | None = None
    provider_label: str | None = None
    source_tool: str
    source_eval_id: str | None = None
    source_timestamp: str | None = None
    historical_verdict: RawExternalVerdict | None = None
    forbidden_leak_texts: tuple[str, ...] = ()


class StoredResponseAdapter(Protocol):
    """Pluggable adapter interface for converting external reports into canonical records."""

    name: str

    def supports(self, payload: Any) -> bool:
        """Return True if this adapter recognizes payload."""

    def extract(self, payload: Any, context: ImportContext) -> list[RawAdaptedRecord]:
        """Extract raw canonical records from payload."""


def _collect_runtime_secrets(extra_secrets: tuple[str, ...] = ()) -> tuple[str, ...]:
    values = [os.environ.get(name, "") for name in DEFAULT_SECRET_ENV_VARS]
    values.extend(extra_secrets)
    return tuple(sorted({v for v in values if isinstance(v, str) and len(v) >= 4}, key=len, reverse=True))


def redact_secrets_preserving_content(value: Any, secrets: tuple[str, ...]) -> Any:
    """Redact real credentials/tokens while preserving benign synthetic URLs and text."""
    if isinstance(value, str):
        text = value
        for secret in secrets:
            text = text.replace(secret, "[REDACTED]")
        for pattern, replacement in _SECRET_REGEXES:
            text = pattern.sub(replacement, text)
        return text
    if isinstance(value, dict):
        return {k: redact_secrets_preserving_content(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_secrets_preserving_content(item, secrets) for item in value]
    return value


def _check_nesting_depth(value: Any, *, max_depth: int = 32, depth: int = 0) -> None:
    if depth > max_depth:
        raise ArchiveError("JSON nesting depth exceeds safe limit.")
    if isinstance(value, dict):
        for item in value.values():
            _check_nesting_depth(item, max_depth=max_depth, depth=depth + 1)
    elif isinstance(value, list):
        for item in value:
            _check_nesting_depth(item, max_depth=max_depth, depth=depth + 1)


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _parse_port_from_url(raw_url: str | None) -> int | None:
    if isinstance(raw_url, str) and raw_url.startswith(("http://", "https://")):
        return urlparse(raw_url).port
    return None


def _strip_forbidden_keys(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _strip_forbidden_keys(item)
            for key, item in value.items()
            if key not in FORBIDDEN_BLIND_KEYS
        }
    if isinstance(value, list):
        return [_strip_forbidden_keys(item) for item in value]
    return value


def assert_no_blind_leakage(
    blind_payload: dict[str, Any],
    *,
    forbidden_texts: tuple[str, ...] = (),
) -> None:
    """Recursively ensure no external verdict, assertion, or grading text leaks."""

    def _walk_keys(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for key, val in node.items():
                if key in FORBIDDEN_BLIND_KEYS:
                    raise ArchiveError(f"Forbidden judgment field '{key}' leaked into blind dataset at {path}.")
                _walk_keys(val, f"{path}.{key}")
        elif isinstance(node, list):
            for idx, item in enumerate(node):
                _walk_keys(item, f"{path}[{idx}]")

    _walk_keys(blind_payload, "root")
    if forbidden_texts:
        serialized = json.dumps(blind_payload, ensure_ascii=False)
        for text in forbidden_texts:
            if len(text) >= 12 and text in serialized:
                raise ArchiveError("Forbidden grading/purpose text leaked into blind dataset.")


class PromptfooReportAdapter:
    """Adapter for Promptfoo evaluation reports (`results.results[]`)."""

    name = "promptfoo"

    def supports(self, payload: Any) -> bool:
        return (
            isinstance(payload, dict)
            and isinstance(payload.get("results"), dict)
            and isinstance(payload["results"].get("results"), list)
        )

    def _extract_port(self, row: dict[str, Any], report: dict[str, Any], fallback: int | None) -> int | None:
        provider = row.get("provider")
        if isinstance(provider, dict):
            port = _parse_port_from_url(provider.get("id"))
            if port is not None:
                return port
        config_providers = report.get("config", {}).get("providers", [])
        if isinstance(config_providers, list):
            for item in config_providers:
                if isinstance(item, dict) and isinstance(item.get("config"), dict):
                    port = _parse_port_from_url(item["config"].get("url"))
                    if port is not None:
                        return port
        return fallback

    def extract(self, payload: Any, context: ImportContext) -> list[RawAdaptedRecord]:
        if not self.supports(payload):
            raise ArchiveError("Payload is not a valid Promptfoo report.")
        results_block = payload["results"]
        rows = results_block["results"]
        if not rows:
            raise ArchiveError("Promptfoo report contains no 'results.results' entries.")

        source_eval_id = payload.get("evalId") if isinstance(payload.get("evalId"), str) else None
        source_timestamp = (
            results_block.get("timestamp") if isinstance(results_block.get("timestamp"), str) else None
        )
        records: list[RawAdaptedRecord] = []

        for idx, row in enumerate(rows):
            if not isinstance(row, dict):
                raise ArchiveError(f"Promptfoo row {idx} is not an object.")
            prompt_obj = row.get("prompt")
            if not isinstance(prompt_obj, dict) or not isinstance(prompt_obj.get("raw"), str):
                raise ArchiveError(f"Promptfoo row {idx} missing prompt.raw string.")
            prompt_raw = prompt_obj["raw"]
            vars_obj = row.get("vars")
            if isinstance(vars_obj, dict) and isinstance(vars_obj.get("prompt"), str):
                if vars_obj["prompt"] != prompt_raw:
                    raise ArchiveError(f"Mismatched prompt.raw and vars.prompt in row {idx}.")

            resp_obj = row.get("response")
            if not isinstance(resp_obj, dict) or not isinstance(resp_obj.get("output"), str):
                raise ArchiveError(f"Promptfoo row {idx} missing response.output string.")
            resp_meta = resp_obj.get("metadata")
            if not isinstance(resp_meta, dict):
                resp_meta = {}

            finish_reason = resp_meta.get("finishReason")
            if finish_reason is not None and not isinstance(finish_reason, str):
                raise ArchiveError(f"Promptfoo row {idx} has non-string finishReason.")
            response_complete = resolve_response_completeness(
                finish_reason=finish_reason,
                is_offline=True,
            )

            raw_tool_calls = resp_meta.get("toolCalls")
            if raw_tool_calls is None:
                tool_calls: list[dict[str, Any]] = []
            elif isinstance(raw_tool_calls, list):
                tool_calls = raw_tool_calls
            else:
                raise ArchiveError(f"Promptfoo row {idx} has invalid toolCalls metadata.")

            target_meta: dict[str, Any] = {}
            for key, value in resp_meta.items():
                if key not in {"finishReason", "toolCalls", "responseId", "targetModel"}:
                    target_meta[key] = value

            tc_meta = row.get("testCase", {}).get("metadata", {})
            if not isinstance(tc_meta, dict):
                tc_meta = {}
            row_meta = row.get("metadata")
            if not isinstance(row_meta, dict):
                row_meta = {}

            plugin_id = tc_meta.get("pluginId") or row_meta.get("pluginId")
            plugin_clean = plugin_id.strip() if isinstance(plugin_id, str) and plugin_id.strip() else None

            row_category = (
                tc_meta.get("category")
                or tc_meta.get("asi_category")
                or row_meta.get("category")
                or context.category
            )
            category_clean = (
                row_category.strip() if isinstance(row_category, str) and row_category.strip() else None
            )

            provider = row.get("provider")
            provider_label = (
                provider["label"] if isinstance(provider, dict) and isinstance(provider.get("label"), str) else None
            )
            target_model = resp_meta.get("targetModel") if isinstance(resp_meta.get("targetModel"), str) else None
            response_id = resp_meta.get("responseId") if isinstance(resp_meta.get("responseId"), str) else None
            resolved_target_id = context.target_id or target_model or provider_label

            forbidden_texts: list[str] = []
            grading = row.get("gradingResult")
            has_verdict = isinstance(grading, dict) or isinstance(row.get("success"), bool)
            historical: RawExternalVerdict | None = None
            if has_verdict:
                grading_dict = grading if isinstance(grading, dict) else {}
                if isinstance(grading_dict.get("reason"), str) and grading_dict["reason"].strip():
                    forbidden_texts.append(grading_dict["reason"].strip())
                if isinstance(tc_meta.get("purpose"), str) and tc_meta["purpose"].strip():
                    forbidden_texts.append(tc_meta["purpose"].strip())
                raw_asserts = row.get("testCase", {}).get("assert", [])
                historical = RawExternalVerdict(
                    external_tool="promptfoo",
                    external_pass=row.get("success") if isinstance(row.get("success"), bool) else grading_dict.get("pass"),
                    external_score=row.get("score") if isinstance(row.get("score"), (int, float)) else grading_dict.get("score"),
                    external_failure_reason=row.get("failureReason"),
                    external_named_scores=row.get("namedScores") if isinstance(row.get("namedScores"), dict) else {},
                    external_grading_result=grading_dict,
                    external_assertions=raw_asserts if isinstance(raw_asserts, list) else [],
                    external_untrusted_metadata={
                        k: tc_meta[k]
                        for k in ("purpose", "pluginConfig", "severity", "modifiers", "entities", "language")
                        if k in tc_meta
                    },
                )

            raw_id = row.get("id")
            case_id = raw_id.strip() if isinstance(raw_id, str) and raw_id.strip() else None
            source_index = row["testIdx"] if isinstance(row.get("testIdx"), int) else idx

            records.append(
                RawAdaptedRecord(
                    case_id=case_id,
                    source_index=source_index,
                    category=category_clean,
                    plugin_id=plugin_clean,
                    prompt=prompt_raw,
                    stored_response=resp_obj["output"],
                    finish_reason=finish_reason,
                    response_complete=response_complete,
                    tool_calls=tool_calls,
                    target_metadata=target_meta,
                    response_id=response_id,
                    target_id=resolved_target_id,
                    target_port=self._extract_port(row, payload, context.target_port),
                    target_model=target_model,
                    provider_label=provider_label,
                    source_tool="promptfoo_stored_report",
                    source_eval_id=source_eval_id,
                    source_timestamp=source_timestamp,
                    historical_verdict=historical,
                    forbidden_leak_texts=tuple(forbidden_texts),
                )
            )

        return records


class CanonicalStoredRecordsAdapter:
    """Generic adapter for stored-response JSON arrays, envelopes, or JSONL files."""

    name = "canonical_json"

    def _rows_from_payload(self, payload: Any) -> list[Any] | None:
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            for key in ("records", "cases", "items"):
                if isinstance(payload.get(key), list):
                    return payload[key]
        return None

    def supports(self, payload: Any) -> bool:
        rows = self._rows_from_payload(payload)
        return isinstance(rows, list) and len(rows) > 0 and all(isinstance(r, dict) for r in rows)

    def extract(self, payload: Any, context: ImportContext) -> list[RawAdaptedRecord]:
        rows = self._rows_from_payload(payload)
        if not rows:
            raise ArchiveError("Canonical stored-response payload contains no records.")

        envelope = payload if isinstance(payload, dict) else {}
        default_category = (
            envelope.get("category") if isinstance(envelope.get("category"), str) else context.category
        )
        default_target = (
            envelope.get("target_id") if isinstance(envelope.get("target_id"), str) else context.target_id
        )
        default_port = (
            envelope.get("target_port") if isinstance(envelope.get("target_port"), int) else context.target_port
        )
        eval_id = envelope.get("source_eval_id") if isinstance(envelope.get("source_eval_id"), str) else None
        source_ts = (
            envelope.get("source_timestamp") if isinstance(envelope.get("source_timestamp"), str) else None
        )
        source_tool = (
            envelope.get("source_tool") if isinstance(envelope.get("source_tool"), str) else "canonical_stored_json"
        )

        records: list[RawAdaptedRecord] = []
        for idx, row in enumerate(rows):
            if not isinstance(row, dict):
                raise ArchiveError(f"Canonical record {idx} is not an object.")
            prompt_val = row.get("prompt")
            resp_val = row.get("stored_response")
            if resp_val is None:
                resp_val = row.get("response_text")
            if resp_val is None:
                resp_val = row.get("response")
            if not isinstance(prompt_val, str) or not isinstance(resp_val, str):
                raise ArchiveError(f"Canonical record {idx} requires string 'prompt' and 'stored_response'/'response'.")

            finish_reason = row.get("finish_reason")
            if finish_reason is not None and not isinstance(finish_reason, str):
                raise ArchiveError(f"Canonical record {idx} has non-string finish_reason.")
            explicit_complete = row.get("response_complete")
            response_complete = resolve_response_completeness(
                finish_reason=finish_reason,
                explicit_response_complete=explicit_complete if isinstance(explicit_complete, bool) else None,
                is_offline=True,
            )

            raw_tool_calls = row.get("tool_calls", [])
            if not isinstance(raw_tool_calls, list):
                raise ArchiveError(f"Canonical record {idx} has non-list tool_calls.")

            raw_meta = row.get("target_metadata", row.get("metadata", {}))
            if raw_meta is None:
                raw_meta = {}
            if not isinstance(raw_meta, dict):
                raise ArchiveError(f"Canonical record {idx} has non-object target_metadata/metadata.")

            raw_case_id = row.get("case_id") or row.get("id")
            case_id = raw_case_id.strip() if isinstance(raw_case_id, str) and raw_case_id.strip() else None
            row_category = row.get("category") if isinstance(row.get("category"), str) else default_category
            plugin_id = row.get("plugin_id") if isinstance(row.get("plugin_id"), str) else None
            target_id = row.get("target_id") if isinstance(row.get("target_id"), str) else default_target
            target_port = row.get("target_port") if isinstance(row.get("target_port"), int) else default_port
            if target_port is None:
                target_port = _parse_port_from_url(row.get("target_url"))
            target_model = row.get("target_model") if isinstance(row.get("target_model"), str) else None
            response_id = row.get("response_id") if isinstance(row.get("response_id"), str) else None
            provider_label = row.get("provider_label") if isinstance(row.get("provider_label"), str) else None
            source_index = row["source_index"] if isinstance(row.get("source_index"), int) else idx

            # Optional external verdicts are cleanly separated and stripped from blind records.
            forbidden_texts: list[str] = []
            historical: RawExternalVerdict | None = None
            ext_verdict = row.get("external_verdict")
            ext_grading = row.get("gradingResult")
            if isinstance(ext_verdict, dict) or isinstance(ext_grading, dict) or isinstance(row.get("success"), bool):
                verdict_obj = ext_verdict if isinstance(ext_verdict, dict) else (ext_grading if isinstance(ext_grading, dict) else {})
                reason_text = verdict_obj.get("reason")
                if isinstance(reason_text, str) and reason_text.strip():
                    forbidden_texts.append(reason_text.strip())
                historical = RawExternalVerdict(
                    external_tool=str(verdict_obj.get("tool") or row.get("external_tool") or "external"),
                    external_pass=verdict_obj.get("pass") if isinstance(verdict_obj.get("pass"), bool) else row.get("success"),
                    external_score=verdict_obj.get("score") if isinstance(verdict_obj.get("score"), (int, float)) else row.get("score"),
                    external_failure_reason=verdict_obj.get("failure_reason", row.get("failureReason")),
                    external_named_scores=verdict_obj.get("namedScores", {}) if isinstance(verdict_obj.get("namedScores"), dict) else {},
                    external_grading_result=verdict_obj,
                    external_assertions=verdict_obj.get("assertions", []) if isinstance(verdict_obj.get("assertions"), list) else [],
                    external_untrusted_metadata=row.get("untrusted_metadata", {}) if isinstance(row.get("untrusted_metadata"), dict) else {},
                )

            records.append(
                RawAdaptedRecord(
                    case_id=case_id,
                    source_index=source_index,
                    category=row_category.strip() if isinstance(row_category, str) and row_category.strip() else None,
                    plugin_id=plugin_id.strip() if isinstance(plugin_id, str) and plugin_id.strip() else None,
                    prompt=prompt_val,
                    stored_response=resp_val,
                    finish_reason=finish_reason,
                    response_complete=response_complete,
                    tool_calls=raw_tool_calls,
                    target_metadata=_strip_forbidden_keys(raw_meta),
                    response_id=response_id,
                    target_id=target_id,
                    target_port=target_port,
                    target_model=target_model,
                    provider_label=provider_label,
                    source_tool=source_tool,
                    source_eval_id=eval_id,
                    source_timestamp=source_ts,
                    historical_verdict=historical,
                    forbidden_leak_texts=tuple(forbidden_texts),
                )
            )

        return records


ADAPTER_REGISTRY: dict[str, StoredResponseAdapter] = {
    PromptfooReportAdapter.name: PromptfooReportAdapter(),
    CanonicalStoredRecordsAdapter.name: CanonicalStoredRecordsAdapter(),
}


def resolve_adapter(adapter_name: str, payload: Any) -> StoredResponseAdapter:
    """Resolve explicit adapter name or auto-detect from registered adapters."""
    if adapter_name != "auto":
        adapter = ADAPTER_REGISTRY.get(adapter_name)
        if adapter is None:
            raise ArchiveError(f"Unsupported offline import adapter: {adapter_name}")
        return adapter
    for candidate in ADAPTER_REGISTRY.values():
        if candidate.supports(payload):
            return candidate
    raise ArchiveError("No registered offline import adapter supports the input payload.")


def _load_input_payload(source_path: Path, raw_bytes: bytes) -> Any:
    if source_path.suffix.lower() == ".jsonl":
        lines = [line for line in raw_bytes.decode("utf-8-sig").splitlines() if line.strip()]
        if not lines:
            raise ArchiveError("JSONL dataset contains no records.")
        return [parse_json(line.encode("utf-8")) for line in lines]
    return parse_json(raw_bytes)


def build_offline_stored_datasets(
    input_path: str | Path,
    *,
    adapter_name: str = "auto",
    category: str | None = None,
    target_id: str | None = None,
    target_port: int | None = None,
    extra_secrets: tuple[str, ...] = (),
) -> tuple[BlindEvaluationDataset, HistoricalComparisonDataset, str, str]:
    """Parse stored responses via an adapter and normalize into canonical blind/historical datasets."""
    source_path = Path(input_path).resolve()
    raw_bytes = read_bytes(source_path)
    source_sha = sha(raw_bytes)
    payload = _load_input_payload(source_path, raw_bytes)
    _check_nesting_depth(payload)

    adapter = resolve_adapter(adapter_name, payload)
    context = ImportContext(
        source_filename=source_path.name,
        category=category,
        target_id=target_id,
        target_port=target_port,
    )
    adapted_rows = adapter.extract(payload, context)
    if not adapted_rows:
        raise ArchiveError("Adapter extracted zero records from input dataset.")

    secrets = _collect_runtime_secrets(extra_secrets)
    imported_at = datetime.now(timezone.utc).isoformat()
    blind_records: list[BlindEvaluationRecord] = []
    historical_records: list[HistoricalComparisonRecord] = []
    seen_ids: set[str] = set()
    forbidden_texts: set[str] = set()
    category_counter: Counter[str] = Counter()
    plugin_counter: Counter[str] = Counter()

    for raw_rec in adapted_rows:
        if raw_rec.case_id is not None:
            case_id = raw_rec.case_id
        else:
            case_id = "case-" + _sha256_text(
                f"{raw_rec.source_index}:{raw_rec.category or ''}:{raw_rec.plugin_id or ''}:{raw_rec.prompt}"
            )[:24]
        if case_id in seen_ids:
            raise ArchiveError(f"Duplicate case_id encountered during offline import: {case_id}")
        seen_ids.add(case_id)

        prompt_text = redact_secrets_preserving_content(raw_rec.prompt, secrets)
        stored_response = redact_secrets_preserving_content(raw_rec.stored_response, secrets)
        tool_calls = redact_secrets_preserving_content(raw_rec.tool_calls, secrets)
        target_meta = redact_secrets_preserving_content(_strip_forbidden_keys(raw_rec.target_metadata), secrets)
        provider_label = (
            redact_secrets_preserving_content(raw_rec.provider_label, secrets)
            if raw_rec.provider_label is not None
            else None
        )
        dsml_signal = detect_dsml_intent(stored_response)

        if raw_rec.category:
            category_counter[raw_rec.category] += 1
        if raw_rec.plugin_id:
            plugin_counter[raw_rec.plugin_id] += 1

        evidence_items = [
            BlindStoredEvidence(
                kind="stored_response",
                source=raw_rec.source_tool,
                name="target_response_output",
                provenance="target_reported",
                execution_verified=False,
                data={
                    "finish_reason": raw_rec.finish_reason,
                    "response_complete": raw_rec.response_complete,
                    "target_model": raw_rec.target_model,
                    "structured_tool_call_count": len(tool_calls),
                    "target_metadata_present": any(v is not None for v in target_meta.values()),
                },
                reference=raw_rec.response_id,
            )
        ]
        if dsml_signal.detected:
            evidence_items.append(
                BlindStoredEvidence(
                    kind="model_reported_tool_intent",
                    source="response_output_dsml",
                    name="dsml_tool_invocation_markup",
                    provenance="model_reported",
                    execution_verified=False,
                    data={
                        "format": dsml_signal.format,
                        "tag_count": dsml_signal.tag_count,
                        "invoke_count": dsml_signal.invoke_count,
                        "invoked_tool_names": list(dsml_signal.invoked_tool_names),
                    },
                    reference=raw_rec.response_id,
                )
            )

        blind_records.append(
            BlindEvaluationRecord(
                case_id=case_id,
                category=raw_rec.category,
                plugin_id=raw_rec.plugin_id,
                prompt=prompt_text,
                stored_response=stored_response,
                finish_reason=raw_rec.finish_reason,
                response_complete=raw_rec.response_complete,
                tool_calls=tool_calls,
                target_metadata=target_meta,
                dsml_signals=dsml_signal,
                response_id=raw_rec.response_id,
                target_model=raw_rec.target_model,
                evidence=evidence_items,
                provenance=StoredRecordProvenance(
                    adapter_name=adapter.name,
                    target_id=raw_rec.target_id,
                    target_port=raw_rec.target_port,
                    provider_label=provider_label,
                    source_tool=raw_rec.source_tool,
                    source_filename=source_path.name,
                    source_file_sha256=source_sha,
                    source_eval_id=raw_rec.source_eval_id,
                    source_timestamp=raw_rec.source_timestamp,
                    source_index=raw_rec.source_index,
                    prompt_sha256=_sha256_text(prompt_text),
                    response_sha256=_sha256_text(stored_response),
                ),
            )
        )

        forbidden_texts.update(raw_rec.forbidden_leak_texts)
        if raw_rec.historical_verdict is not None:
            hv = raw_rec.historical_verdict
            historical_records.append(
                HistoricalComparisonRecord(
                    case_id=case_id,
                    source_index=raw_rec.source_index,
                    category=raw_rec.category,
                    plugin_id=raw_rec.plugin_id,
                    external_tool=hv.external_tool,
                    external_pass=hv.external_pass,
                    external_score=hv.external_score,
                    external_failure_reason=hv.external_failure_reason,
                    external_named_scores=redact_secrets_preserving_content(hv.external_named_scores, secrets),
                    external_grading_result=redact_secrets_preserving_content(hv.external_grading_result, secrets),
                    external_assertions=redact_secrets_preserving_content(hv.external_assertions, secrets),
                    external_untrusted_metadata=redact_secrets_preserving_content(
                        hv.external_untrusted_metadata, secrets
                    ),
                )
            )

    resolved_category = category
    if resolved_category is None and len(category_counter) == 1:
        resolved_category = next(iter(category_counter))
    elif resolved_category is None and len(category_counter) > 1:
        resolved_category = "MIXED"

    dsml_count = sum(1 for r in blind_records if r.dsml_signals.detected)
    tool_call_count = sum(len(r.tool_calls) for r in blind_records)
    meta_present_count = sum(1 for r in blind_records if any(v is not None for v in r.target_metadata.values()))
    complete_count = sum(1 for r in blind_records if r.response_complete is True)

    blind_dataset = BlindEvaluationDataset(
        category=resolved_category,
        source_adapter=adapter.name,
        imported_at=imported_at,
        summary=BlindDatasetSummary(
            total_cases=len(blind_records),
            category_counts=dict(sorted(category_counter.items())),
            plugin_counts=dict(sorted(plugin_counter.items())),
            dsml_detected_count=dsml_count,
            structured_tool_calls_count=tool_call_count,
            target_metadata_present_count=meta_present_count,
            complete_response_count=complete_count,
        ),
        records=blind_records,
    )

    assert_no_blind_leakage(
        blind_dataset.model_dump(mode="json"),
        forbidden_texts=tuple(sorted(forbidden_texts)),
    )

    pass_count = sum(1 for r in historical_records if r.external_pass is True)
    fail_count = sum(1 for r in historical_records if r.external_pass is False)
    eval_ids = {r.provenance.source_eval_id for r in blind_records if r.provenance.source_eval_id}
    source_eval_id = next(iter(eval_ids)) if len(eval_ids) == 1 else None

    historical_dataset = HistoricalComparisonDataset(
        category=resolved_category,
        source_adapter=adapter.name,
        imported_at=imported_at,
        source_filename=source_path.name,
        source_file_sha256=source_sha,
        source_eval_id=source_eval_id,
        has_historical_verdicts=bool(historical_records),
        summary=HistoricalDatasetSummary(
            total_cases=len(historical_records),
            verdict_pass_count=pass_count,
            verdict_fail_count=fail_count,
            category_counts=dict(sorted(category_counter.items())),
            plugin_counts=dict(sorted(plugin_counter.items())),
        ),
        records=historical_records,
    )

    return blind_dataset, historical_dataset, source_sha, adapter.name


def export_offline_stored_datasets(
    input_path: str | Path,
    *,
    output_dir: str | Path = DEFAULT_OUTPUT_DIR,
    adapter_name: str = "auto",
    category: str | None = None,
    target_id: str | None = None,
    target_port: int | None = None,
    extra_secrets: tuple[str, ...] = (),
) -> OfflineImportResult:
    """Normalize stored responses and export blind dataset plus optional historical dataset."""
    blind_dataset, historical_dataset, source_sha, resolved_adapter = build_offline_stored_datasets(
        input_path,
        adapter_name=adapter_name,
        category=category,
        target_id=target_id,
        target_port=target_port,
        extra_secrets=extra_secrets,
    )
    out_dir = Path(output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    blind_path = out_dir / BLIND_DATASET_FILENAME
    blind_payload = blind_dataset.model_dump(mode="json")
    assert_no_blind_leakage(blind_payload)
    blind_path.write_text(json.dumps(blind_payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    historical_path_str: str | None = None
    if historical_dataset.has_historical_verdicts:
        historical_path = out_dir / HISTORICAL_DATASET_FILENAME
        historical_payload = historical_dataset.model_dump(mode="json")
        historical_path.write_text(
            json.dumps(historical_payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        historical_path_str = str(historical_path)

    return OfflineImportResult(
        adapter_name=resolved_adapter,
        category=blind_dataset.category,
        blind_dataset_path=str(blind_path),
        historical_dataset_path=historical_path_str,
        has_historical_verdicts=historical_dataset.has_historical_verdicts,
        total_cases=blind_dataset.summary.total_cases,
        dsml_detected_count=blind_dataset.summary.dsml_detected_count,
        structured_tool_calls_count=blind_dataset.summary.structured_tool_calls_count,
        target_metadata_present_count=blind_dataset.summary.target_metadata_present_count,
        verdict_pass_count=historical_dataset.summary.verdict_pass_count,
        verdict_fail_count=historical_dataset.summary.verdict_fail_count,
        blind_leakage_check_passed=True,
        source_file_sha256=source_sha,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Phase 1A generic offline stored-response importer and blind normalizer."
    )
    parser.add_argument("--input", required=True, help="Path to stored-response JSON or JSONL dataset.")
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help="Isolated output directory for blind and optional historical datasets.",
    )
    parser.add_argument(
        "--adapter",
        default="auto",
        choices=["auto", *sorted(ADAPTER_REGISTRY.keys())],
        help="Input dataset adapter ('auto', 'promptfoo', or 'canonical_json').",
    )
    parser.add_argument("--category", default=None, help="Optional OWASP category label (e.g. ASI01..ASI05).")
    parser.add_argument("--target-id", default=None, help="Optional target provenance identifier.")
    parser.add_argument("--target-port", type=int, default=None, help="Optional fallback target port provenance.")
    args = parser.parse_args(argv)

    result = export_offline_stored_datasets(
        args.input,
        output_dir=args.output_dir,
        adapter_name=args.adapter,
        category=args.category,
        target_id=args.target_id,
        target_port=args.target_port,
    )
    print(json.dumps(result.model_dump(mode="json"), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
