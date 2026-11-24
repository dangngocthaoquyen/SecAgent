"""Normalizer for custom testcase datasets with untrusted upload validation."""

from datetime import datetime, timezone
from hashlib import sha256
import json
import re
from typing import Any

from workflow.dataset_models import DatasetEnvelope, ImportedTestcase

MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB
MAX_CASES = 100
MAX_PROMPT_LENGTH = 65536
MAX_ID_LENGTH = 4096


class DatasetValidationError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _check_nesting_depth(value: Any, current_depth: int = 0, max_depth: int = 10) -> None:
    if current_depth > max_depth:
        raise DatasetValidationError("excessive_nesting", "JSON structure exceeds maximum allowed nesting depth.")
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeError as exc:
            raise DatasetValidationError("invalid_unicode", "Unpaired Unicode surrogates are unsupported.") from exc
    if isinstance(value, float):
        import math
        if not math.isfinite(value):
            raise DatasetValidationError("malformed_json", "Nonfinite JSON numbers are unsupported.")
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str) or len(k) > 256:
                raise DatasetValidationError("invalid_key", "Dictionary keys must be strings of at most 256 characters.")
            if k.startswith("__") or k in {"prototype", "constructor"}:
                raise DatasetValidationError("unsafe_key", f"Unsafe dictionary key {k!r} detected.")
            _check_nesting_depth(v, current_depth + 1, max_depth)
    elif isinstance(value, list):
        for item in value:
            _check_nesting_depth(item, current_depth + 1, max_depth)


def normalize_dataset(raw_bytes: bytes, filename: str = "dataset.json") -> DatasetEnvelope:
    """Validate untrusted uploaded bytes and map to canonical DatasetEnvelope."""
    if not raw_bytes:
        raise DatasetValidationError("empty_file", "Uploaded file is empty.")
    if len(raw_bytes) > MAX_FILE_BYTES:
        raise DatasetValidationError("file_too_large", f"File exceeds maximum allowed size of {MAX_FILE_BYTES} bytes.")

    try:
        decoded = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DatasetValidationError("invalid_encoding", "Dataset must be valid UTF-8 text.") from exc

    try:
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise DatasetValidationError("duplicate_json_key", "Duplicate JSON object key.")
                result[key] = value
            return result
        lower_name = filename.lower()
        if lower_name.endswith((".yaml", ".yml")):
            import yaml
            data = yaml.safe_load(decoded)
        elif lower_name.endswith(".jsonl"):
            lines = [ln for ln in decoded.splitlines() if ln.strip()]
            if not lines:
                raise DatasetValidationError("empty_testcases", "JSONL dataset contains no records.")
            data = [
                json.loads(
                    ln,
                    object_pairs_hook=pairs,
                    parse_constant=lambda _: (_ for _ in ()).throw(
                        DatasetValidationError("malformed_json", "Nonfinite JSON number.")
                    ),
                )
                for ln in lines
            ]
        else:
            data = json.loads(
                decoded,
                object_pairs_hook=pairs,
                parse_constant=lambda _: (_ for _ in ()).throw(
                    DatasetValidationError("malformed_json", "Nonfinite JSON number.")
                ),
            )
    except json.JSONDecodeError as exc:
        raise DatasetValidationError("malformed_json", f"Invalid JSON syntax at line {exc.lineno}, column {exc.colno}.") from exc
    except Exception as exc:
        if isinstance(exc, DatasetValidationError):
            raise
        raise DatasetValidationError("malformed_json", f"Invalid dataset syntax: {exc}") from exc

    _check_nesting_depth(data, current_depth=0, max_depth=10)

    file_hash = sha256(raw_bytes).hexdigest()
    clean_name = re.sub(r"[^\w\s.-]", "", filename).strip()[:120] or "custom-dataset.json"

    # Format P: Promptfoo evaluation report JSON (`results.results[]`) or canonical stored-response records (`records[]` / `cases[]`)
    is_promptfoo_report = (
        isinstance(data, dict)
        and (
            ("results" in data and ("table" in data or "evalId" in data or "stats" in data))
            or ("version" in data and "results" in data and isinstance(data.get("results"), dict) and "results" in data["results"])
        )
    )
    is_stored_records_envelope = (
        isinstance(data, dict)
        and "testcases" not in data
        and any(isinstance(data.get(k), list) for k in ("records", "cases"))
    )

    if is_promptfoo_report or is_stored_records_envelope:
        from testing.archived_crosscheck import ArchiveError
        from testing.offline_stored_import import (
            CanonicalStoredRecordsAdapter,
            ImportContext,
            PromptfooReportAdapter,
        )

        adapter = PromptfooReportAdapter() if is_promptfoo_report else CanonicalStoredRecordsAdapter()
        if not adapter.supports(data):
            raise DatasetValidationError("invalid_envelope", "Stored response report structure is invalid.")
        try:
            adapted_records = adapter.extract(
                data,
                ImportContext(
                    source_filename=clean_name,
                    category=data.get("category") if isinstance(data.get("category"), str) else None,
                    target_id=data.get("target_id") if isinstance(data.get("target_id"), str) else None,
                ),
            )
        except ArchiveError as exc:
            raise DatasetValidationError("invalid_stored_report", str(exc)) from exc

        if not adapted_records:
            raise DatasetValidationError("empty_testcases", "Dataset must contain at least one testcase.")
        if len(adapted_records) > MAX_CASES:
            raise DatasetValidationError(
                "too_many_testcases",
                f"Dataset contains {len(adapted_records)} testcases, exceeding maximum limit of {MAX_CASES}.",
            )

        normalized_cases: list[ImportedTestcase] = []
        seen_ids: set[str] = set()
        for idx, rec in enumerate(adapted_records):
            case_id = rec.case_id or f"TC{idx + 1:04d}"
            if case_id in seen_ids:
                raise DatasetValidationError(
                    "duplicate_testcase_id",
                    f"Duplicate testcase ID {case_id!r} detected in dataset.",
                )
            seen_ids.add(case_id)
            if not rec.prompt:
                raise DatasetValidationError("empty_prompt", f"Prompt in testcase {case_id} must not be empty.")
            prompt_hash = sha256(rec.prompt.encode("utf-8")).hexdigest()
            meta: dict[str, Any] = {**rec.target_metadata}
            if rec.category:
                meta["asi_category"] = rec.category
            if rec.plugin_id:
                meta.setdefault("pluginId", rec.plugin_id)
            resolved_rec_source = (
                "canonical_stored_jsonl"
                if lower_name.endswith(".jsonl") and not is_promptfoo_report and not (isinstance(data, dict) and data.get("source_tool"))
                else rec.source_tool
            )
            extra_obj: dict[str, Any] = {
                "stored_response": rec.stored_response,
                "finish_reason": rec.finish_reason,
                "response_complete": rec.response_complete,
                "tool_calls": rec.tool_calls,
                "response_id": rec.response_id,
                "target_model": rec.target_model,
                "provider_label": rec.provider_label,
                "source_tool": resolved_rec_source,
                "source_eval_id": rec.source_eval_id,
                "source_timestamp": rec.source_timestamp,
            }
            if rec.historical_verdict is not None:
                extra_obj["historical_verdict"] = rec.historical_verdict.model_dump(mode="json")

            normalized_cases.append(
                ImportedTestcase(
                    internal_id="import-" + sha256(f"{file_hash}:{idx}".encode()).hexdigest()[:24],
                    source_case={"case_id": case_id, "prompt": rec.prompt},
                    testcase_id=case_id,
                    description=None,
                    plugin_id=rec.plugin_id,
                    strategy_id=None,
                    prompt=rec.prompt,
                    prompt_sha256=prompt_hash,
                    assertions=[],
                    metadata=meta,
                    options={},
                    extra=extra_obj,
                    index=idx,
                )
            )

        dataset_id = sha256(f"{file_hash}:{len(normalized_cases)}".encode("utf-8")).hexdigest()[:32]
        now = datetime.now(timezone.utc).isoformat()
        envelope = DatasetEnvelope(
            content_sha256="0" * 64,
            dataset_id=dataset_id,
            name=clean_name,
            schema_version="1.0",
            source_tool="promptfoo_report" if is_promptfoo_report else str(data.get("source_tool") or "canonical_stored_json"),
            platform=str(data.get("platform")) if data.get("platform") is not None else None,
            bot=str(data.get("bot")) if data.get("bot") is not None else None,
            run_id=str(data.get("evalId") or data.get("run_id"))[:64] if (data.get("evalId") or data.get("run_id")) else None,
            imported_at=now,
            file_sha256=file_hash,
            total_testcases=len(normalized_cases),
            testcases=normalized_cases,
            source_metadata={
                "dataset_kind": "stored_response_report",
                "has_stored_responses": True,
                "adapter_name": adapter.name,
            },
        )
        envelope.content_sha256 = envelope.computed_content_sha256()
        envelope._source_bytes = raw_bytes
        return envelope

    # Format A: Object Envelope
    if isinstance(data, dict):
        raw_cases = data.get("testcases")
        if not isinstance(raw_cases, list) and isinstance(data.get("tests"), list):
            raw_cases = data["tests"]
        if not isinstance(raw_cases, list):
            raise DatasetValidationError("invalid_envelope", "Object dataset must contain a 'testcases' list.")
        source_tool = str(data.get("source_tool") or "custom")
        schema_version = str(data.get("schema_version") or "1.0")
        platform = str(data.get("platform")) if data.get("platform") is not None else None
        bot = str(data.get("bot")) if data.get("bot") is not None else None
        run_id = str(data.get("run_id")) if data.get("run_id") is not None else None
        source_metadata = {k: v for k, v in data.items() if k not in {
            "testcases", "total_testcases", "source_tool", "schema_version", "platform", "bot", "run_id"
        }}
    # Format B: Array of Testcases
    elif isinstance(data, list):
        raw_cases = data
        source_tool = "promptfoo"
        schema_version = "1.0"
        platform = None
        bot = None
        run_id = None
        source_metadata = {}
    else:
        raise DatasetValidationError("invalid_root_shape", "Dataset root must be a JSON object or array.")

    if not raw_cases:
        raise DatasetValidationError("empty_testcases", "Dataset must contain at least one testcase.")
    if len(raw_cases) > MAX_CASES:
        raise DatasetValidationError("too_many_testcases", f"Dataset contains {len(raw_cases)} testcases, exceeding maximum limit of {MAX_CASES}.")

    normalized_cases: list[ImportedTestcase] = []
    seen_ids: set[str] = set()

    for idx, raw_case in enumerate(raw_cases):
        if not isinstance(raw_case, dict):
            raise DatasetValidationError("invalid_testcase_element", f"Testcase at index {idx} must be a JSON object.")

        # ID extraction
        raw_id = raw_case.get("testcase_id", raw_case.get("id"))
        if raw_id is not None:
            if not isinstance(raw_id, str) or not raw_id.strip():
                raise DatasetValidationError("invalid_testcase_id", f"Testcase at index {idx} has an invalid ID.")
            case_id = raw_id
            if len(case_id) > MAX_ID_LENGTH:
                raise DatasetValidationError("testcase_id_too_long", f"Testcase ID at index {idx} exceeds {MAX_ID_LENGTH} characters.")
        else:
            case_id = f"TC{idx + 1:04d}"

        if case_id in seen_ids:
            raise DatasetValidationError("duplicate_testcase_id", f"Duplicate testcase ID {case_id!r} detected in dataset.")
        seen_ids.add(case_id)

        # Prompt extraction
        vars_dict = raw_case.get("vars")
        raw_prompt = None
        if isinstance(vars_dict, dict) and "prompt" in vars_dict:
            raw_prompt = vars_dict["prompt"]
        elif "prompt" in raw_case:
            raw_prompt = raw_case["prompt"]

        if raw_prompt is None:
            raise DatasetValidationError("missing_prompt", f"Testcase {case_id} is missing a prompt in 'vars.prompt' or 'prompt'.")
        if not isinstance(raw_prompt, str):
            raise DatasetValidationError("invalid_prompt_type", f"Prompt in testcase {case_id} must be a string.")
        if not raw_prompt:
            raise DatasetValidationError("empty_prompt", f"Prompt in testcase {case_id} must not be empty.")
        if len(raw_prompt.encode("utf-8")) > MAX_PROMPT_LENGTH:
            raise DatasetValidationError("prompt_too_large", f"Prompt in testcase {case_id} exceeds {MAX_PROMPT_LENGTH} bytes.")

        prompt_hash = sha256(raw_prompt.encode("utf-8")).hexdigest()

        # Description: preserve null
        raw_desc = raw_case.get("description")
        desc = raw_desc

        # Plugin ID
        raw_plugin = raw_case.get("plugin_id", (raw_case.get("metadata") or {}).get("pluginId") if isinstance(raw_case.get("metadata"), dict) else None)
        plugin_id = raw_plugin

        # Strategy ID: preserve null
        raw_strategy = raw_case.get("strategy_id")
        strategy_id = raw_strategy

        # Assertions: accept 'assertions' or 'assert'
        raw_assertions = raw_case.get("assertions", raw_case.get("assert", []))
        if not isinstance(raw_assertions, list):
            raise DatasetValidationError("invalid_assertions", f"Assertions in testcase {case_id} must be a list.")
        assertions: list[dict[str, Any]] = []
        for a_idx, a_val in enumerate(raw_assertions):
            if not isinstance(a_val, dict):
                raise DatasetValidationError("invalid_assertions", "Each assertion must be a JSON object.")
            assertions.append(a_val)

        # Metadata
        raw_meta = raw_case.get("metadata") or {}
        metadata = {str(k): v for k, v in raw_meta.items()} if isinstance(raw_meta, dict) else {}

        # Options & extra
        raw_opts = raw_case.get("options") or {}
        options = {str(k): v for k, v in raw_opts.items()} if isinstance(raw_opts, dict) else {}

        raw_extra = raw_case.get("extra") or {}
        extra = {str(k): v for k, v in raw_extra.items()} if isinstance(raw_extra, dict) else {}

        for key in ("metadata", "options", "extra"):
            if key in raw_case and not isinstance(raw_case[key], dict):
                raise DatasetValidationError("invalid_metadata", "Metadata, options and extra must be JSON objects.")
        for value in (desc, plugin_id, strategy_id):
            if value is not None and not isinstance(value, str):
                raise DatasetValidationError("invalid_metadata", "Description and source labels must be strings or null.")

        normalized_cases.append(ImportedTestcase(
            internal_id="import-" + sha256(f"{file_hash}:{idx}".encode()).hexdigest()[:24],
            source_case=raw_case,
            testcase_id=case_id,
            description=desc,
            plugin_id=plugin_id,
            strategy_id=strategy_id,
            prompt=raw_prompt,
            prompt_sha256=prompt_hash,
            assertions=assertions,
            metadata=metadata,
            options=options,
            extra=extra,
            index=idx,
        ))

    dataset_id = sha256(f"{file_hash}:{len(normalized_cases)}".encode("utf-8")).hexdigest()[:32]
    now = datetime.now(timezone.utc).isoformat()

    envelope = DatasetEnvelope(
        content_sha256="0" * 64,
        dataset_id=dataset_id,
        name=clean_name,
        schema_version=schema_version,
        source_tool=source_tool,
        platform=platform,
        bot=bot,
        run_id=run_id,
        imported_at=now,
        file_sha256=file_hash,
        total_testcases=len(normalized_cases),
        testcases=normalized_cases,
        source_metadata=source_metadata,
    )

    envelope.content_sha256 = envelope.computed_content_sha256()
    envelope._source_bytes = raw_bytes
    return envelope
