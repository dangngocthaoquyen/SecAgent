"""Standalone Flask API routes and security harness for SecAgent G11.3C Generator.

Deliberately independent of `workflow/api.py` (which is shared with parallel G12 work):
- Provides `register_generator_routes(app, ctx)` and `GENERATOR_ROUTE_SPECS` for future
  minimal wiring into `workflow/api.py`.
- Provides `create_standalone_generator_app(...)` inheriting SecAgent's exact loopback,
  Host, Origin, Sec-Fetch-Site, query-string, body-size, JSON-only, validation-nonce
  (`X-SecAgent-Validation`), operator-auth (`X-SecAgent-Operator`), and security header
  boundaries for end-to-end offline testing.
- Enforces API default `deduplicate_across_asi=False` so per-ASI evaluations stay
  independent unless the operator opts into cross-ASI deduplication.
- Rejects raw client credentials, arbitrary provider endpoints, and authority-injection
  fields before calling `GeneratorService`.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from hashlib import sha256
import ipaddress
import json
import re
import secrets
from threading import RLock
import time
from typing import Any, Callable, Mapping

from flask import Flask, jsonify, request
from pydantic import Field, ValidationError, field_validator
from werkzeug.exceptions import HTTPException

from generator.constants import (
    AsiCode,
    DEFAULT_MAX_PER_ASI,
    DEFAULT_MAX_TOTAL_CASES,
    DEFAULT_MIN_PER_ASI,
    DEFAULT_PER_ASI,
    FORBIDDEN_LLM_OUTPUT_KEYS,
    HARD_MAX_PER_ASI,
    HARD_MAX_TOTAL_CASES,
    SUPPORTED_ASI_CODES,
)
from generator.models import StrictGeneratorModel, normalize_asi_code
from generator.orchestrator import (
    GenerateAndRunOrchestrator,
    GenerateAndRunRequest,
    GenerateAndRunRerunRequest,
    OrchestrationError,
)
from generator.preview_store import (
    GeneratorPreviewStore,
    PreviewEditRequest,
    PreviewSaveRequest,
    PreviewStoreError,
)
from generator.provider_factory import detect_client_credential_or_endpoint_injection
from generator.providers.base import ProviderErrorCategory
from generator.readiness import assess_target_readiness
from generator.request_builder import SupportedLanguage
from generator.service import (
    GenerationServiceError,
    GenerationServiceRequest,
    GeneratorService,
)
from generator.skills import GeneratorSkillError, GeneratorSkillLoader
from workflow.dataset_repository import DatasetRepository

GENERATOR_API_DEFAULT_DEDUPLICATE_ACROSS_ASI: bool = False
DEFAULT_GENERATOR_MAX_BODY_BYTES: int = 256 * 1024  # 256 KiB
DEFAULT_GENERATE_RATE_LIMIT_MAX: int = 30
DEFAULT_GENERATE_RATE_LIMIT_WINDOW_SECONDS: float = 60.0

# Exact route table exported for wiring into workflow/api.py boundary().
GENERATOR_EXACT_ROUTES: dict[str, str] = {
    "/api/testing/generator/status": "GET",
    "/api/testing/generator/readiness": "POST",
    "/api/testing/generator/generate": "POST",
    "/api/testing/generator/generate-and-run": "POST",
}
GENERATOR_REGEX_ROUTES: tuple[tuple[str, str], ...] = (
    (r"/api/testing/generator/previews/prev-[a-f0-9]{32}", "GET"),
    (r"/api/testing/generator/previews/prev-[a-f0-9]{32}/edit", "POST"),
    (r"/api/testing/generator/previews/prev-[a-f0-9]{32}/save", "POST"),
    (r"/api/testing/generator/previews/prev-[a-f0-9]{32}/save-status", "GET"),
    (r"/api/testing/generator/generate-and-run/gnr-[a-f0-9]{32}", "GET"),
    (r"/api/testing/generator/generate-and-run/gnr-[a-f0-9]{32}/rerun", "POST"),
    (r"/api/testing/generator/generate-and-run/submission/[a-f0-9]{32}", "GET"),
)


class _StrictApiJsonError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _parse_strict_request_json(raw: bytes, *, max_bytes: int) -> dict[str, Any]:
    """Decode strict UTF-8 JSON object rejecting duplicate keys, NaN/Infinity, and oversized ints."""
    if not raw:
        raise _StrictApiJsonError("empty_request_body", "JSON request body is required.")
    if len(raw) > max_bytes:
        raise _StrictApiJsonError("payload_too_large", "Request body exceeds allowed size limit.")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise _StrictApiJsonError("invalid_json", "Request body must be valid UTF-8 JSON.") from None

    def _no_dups(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in pairs:
            if k in out:
                raise _StrictApiJsonError("duplicate_json_key", "Request JSON contains duplicate keys.")
            out[k] = v
        return out

    def _no_const(_: str) -> Any:
        raise _StrictApiJsonError("invalid_json", "Nonfinite JSON numeric constants are unsupported.")

    try:
        loaded = json.loads(text, object_pairs_hook=_no_dups, parse_constant=_no_const)
    except _StrictApiJsonError:
        raise
    except (json.JSONDecodeError, ValueError):
        raise _StrictApiJsonError("invalid_json", "Request body is not valid JSON.") from None

    if not isinstance(loaded, dict):
        raise _StrictApiJsonError("invalid_request", "Request body must be a JSON object.")
    return loaded


def _contains_forbidden_authority_key(payload: Any) -> bool:
    stack: list[Any] = [payload]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            for key, val in current.items():
                if isinstance(key, str) and key in FORBIDDEN_LLM_OUTPUT_KEYS:
                    return True
                stack.append(val)
        elif isinstance(current, list):
            stack.extend(current)
    return False


class ReadinessApiRequest(StrictGeneratorModel):
    """Validated JSON input for POST /api/testing/generator/readiness."""

    target_id: str = Field(min_length=1, max_length=128)
    selected_asi: tuple[AsiCode, ...] | None = None
    requested_scopes: dict[AsiCode, str] = Field(default_factory=dict)
    policy_ids_by_asi: dict[AsiCode, str] = Field(default_factory=dict)

    @field_validator("target_id")
    @classmethod
    def check_target_id(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("target_id must not be blank.")
        return cleaned

    @field_validator("selected_asi", mode="before")
    @classmethod
    def check_selected_asi(cls, value: Any) -> tuple[AsiCode, ...] | None:
        if value is None:
            return None
        if not isinstance(value, (list, tuple)) or not value:
            raise ValueError("selected_asi must be a non-empty list of ASI codes.")
        resolved: list[AsiCode] = []
        seen: set[AsiCode] = set()
        for item in value:
            code = normalize_asi_code(item)
            if code in seen:
                raise ValueError(f"Duplicate ASI code {code!r} in selected_asi.")
            seen.add(code)
            resolved.append(code)
        return tuple(resolved)

    @field_validator("requested_scopes", "policy_ids_by_asi", mode="before")
    @classmethod
    def check_asi_map(cls, value: Any) -> dict[AsiCode, str]:
        if value is None:
            return {}
        if not isinstance(value, Mapping):
            raise ValueError("ASI mapping must be a JSON object.")
        out: dict[AsiCode, str] = {}
        for k, v in value.items():
            code = normalize_asi_code(k)
            if code in out:
                raise ValueError(f"Duplicate ASI key {code!r}.")
            if not isinstance(v, str) or not v.strip():
                raise ValueError("ASI mapping value must be a non-empty string.")
            out[code] = v.strip()
        return out


class GenerateApiRequest(StrictGeneratorModel):
    """Validated JSON input for POST /api/testing/generator/generate.

    Explicitly defaults `deduplicate_across_asi=False` so per-ASI evaluations remain
    independent unless the operator opts into cross-ASI deduplication.
    """

    target_id: str = Field(min_length=1, max_length=128)
    counts_by_asi: dict[str, int]
    language: SupportedLanguage = "en"
    focus_note: str | None = Field(default=None, max_length=1000)
    requested_scopes: dict[str, str] = Field(default_factory=dict)
    policy_ids_by_asi: dict[str, str] = Field(default_factory=dict)
    deduplicate_across_asi: bool = Field(
        default=GENERATOR_API_DEFAULT_DEDUPLICATE_ACROSS_ASI, strict=True
    )
    max_calls_per_asi: int = Field(default=1, ge=1, le=2, strict=True)
    timeout_seconds: float | None = Field(default=None, gt=0.0, le=120.0, allow_inf_nan=False)

    def to_service_request(self) -> GenerationServiceRequest:
        return GenerationServiceRequest(
            target_id=self.target_id,
            counts_by_asi=self.counts_by_asi,
            language=self.language,
            focus_note=self.focus_note,
            requested_scopes=self.requested_scopes,
            policy_ids_by_asi=self.policy_ids_by_asi,
            deduplicate_across_asi=self.deduplicate_across_asi,
            max_calls_per_asi=self.max_calls_per_asi,
            timeout_seconds=self.timeout_seconds,
        )


class _SlidingWindowRateLimiter:
    """Thread-safe bounded sliding-window rate limiter for generation submissions."""

    def __init__(
        self,
        *,
        max_requests: int,
        window_seconds: float,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._clock = clock or time.monotonic
        self._lock = RLock()
        self._timestamps: deque[float] = deque()

    def allow(self) -> bool:
        with self._lock:
            now = self._clock()
            cutoff = now - self._window_seconds
            while self._timestamps and self._timestamps[0] <= cutoff:
                self._timestamps.popleft()
            if len(self._timestamps) >= self._max_requests:
                return False
            self._timestamps.append(now)
            return True


@dataclass(frozen=True)
class GeneratorApiContext:
    """Dependency injection container for registering Generator API routes."""

    generator_service: GeneratorService
    preview_store: GeneratorPreviewStore
    dataset_repo: DatasetRepository
    catalog: Any
    application_contexts: Any | None
    nonce: str
    operator_authorized: Callable[[], bool]
    operator_identity: Callable[[], str]
    policy_store: Any | None = None
    orchestrator: GenerateAndRunOrchestrator | None = None
    skill_loader: GeneratorSkillLoader | None = None
    fail: Callable[[str, int], Any] | None = None
    max_body_bytes: int = DEFAULT_GENERATOR_MAX_BODY_BYTES
    rate_limit_max_generate_requests: int = DEFAULT_GENERATE_RATE_LIMIT_MAX
    rate_limit_window_seconds: float = DEFAULT_GENERATE_RATE_LIMIT_WINDOW_SECONDS
    clock: Callable[[], float] | None = None


_GENERATOR_ERROR_MESSAGES: dict[str, str] = {
    "local_only": "Generator API accepts loopback requests on allowed local host only.",
    "origin_rejected": "Request Origin or Sec-Fetch-Site header is not allowed.",
    "origin_required": "POST requests require an exact matching local Origin header.",
    "json_required": "POST requests must use Content-Type: application/json.",
    "validation_nonce_required": "A valid X-SecAgent-Validation nonce header is required.",
    "operator_authentication_required": "Operator authentication is required for Generator API operations.",
    "not_found": "Requested Generator API route was not found.",
    "method_not_allowed": "HTTP method is not allowed for this route.",
    "body_not_allowed": "GET requests must not include a request body.",
    "payload_too_large": "Request body exceeds the maximum allowed byte limit.",
    "empty_request_body": "JSON request body is required.",
    "invalid_json": "Request body is not valid UTF-8 JSON.",
    "duplicate_json_key": "Request JSON must not contain duplicate object keys.",
    "invalid_request": "Generator API request payload is invalid.",
    "authority_field_rejected": "Request attempted to inject a forbidden verdict, assertion, or evaluation authority field.",
    "client_credential_or_endpoint_forbidden": "Clients may not supply provider credentials, credential env names, or custom provider endpoints.",
    "raw_credential_in_request_forbidden": "Raw API keys or bearer tokens must not be sent in Generator API requests.",
    "generator_rate_limited": "Generator submission rate limit exceeded; retry later.",
    "generator_credential_unavailable": "Configured backend generator credential is unavailable; check server environment configuration.",
    "target_not_found": "Selected target was not found in the active catalog.",
    "preview_not_found": "Preview record was not found or was cleared after server restart.",
    "preview_access_denied": "Preview belongs to a different operator session.",
    "preview_expired": "Preview has expired. Generate a fresh preview before editing or saving.",
    "preview_already_saved": "Preview was already saved to DatasetRepository.",
    "preview_save_in_progress": "A save operation for this preview is already in progress.",
    "preview_capacity_exceeded": "Active preview capacity reached; save or wait for previews to expire.",
    "preview_has_no_accepted_candidates": "Preview has no accepted candidates to save.",
    "candidate_not_in_preview": "One or more candidate IDs do not belong to this preview.",
    "duplicate_edit_candidate_id": "Duplicate candidate_id supplied in preview edit request.",
    "no_candidates_selected": "Select at least one accepted candidate before saving.",
    "save_confirmation_required": "Explicit save_confirmed=true is required to persist a dataset.",
    "partial_save_confirmation_required": "Partial generation requires partial_save_confirmed=true to save a subset.",
    "preview_target_not_found": "Target profile no longer exists in the catalog.",
    "preview_target_revision_stale": "Target profile revision changed after generation; generate a fresh preview.",
    "preview_context_revision_stale": "Application Context revision changed after generation; generate a fresh preview.",
    "preview_policy_revision_stale": "Reviewed ResponsePolicy changed after generation; generate a fresh preview.",
    "dataset_normalization_failed": "Dataset normalization failed before persistence.",
    "dataset_save_failed": "Dataset persistence failed; preview remains unsaved.",
    "generic_runner_unavailable": "Generic Runner service is unavailable for Generate & Run orchestration.",
    "authorization_required": "Explicit operator authorization_confirmed=true is required before execution.",
    "target_not_authorized": "Selected target has not been reviewed and authorized for live execution.",
    "target_revision_stale": "Target profile revision changed; refresh target configuration before starting.",
    "judge_provider_unavailable": "Hybrid evaluation requested but Judge provider is unavailable.",
    "generate_and_run_submission_conflict": "This submission_id was already used with different Generate & Run parameters.",
    "generate_and_run_submission_in_progress": "An identical Generate & Run submission is currently initializing.",
    "workflow_not_found": "Generate & Run workflow record was not found.",
    "workflow_submission_not_found": "No Generate & Run workflow was found for this submission_id.",
    "workflow_submission_expired": "This submission_id was already used, but its in-memory workflow snapshot has expired.",
    "workflow_execution_in_progress": "Cannot start a rerun while an execution or rerun for this workflow is still active.",
    "workflow_access_denied": "Generate & Run workflow belongs to a different operator session.",
    "dataset_not_available_for_rerun": "Workflow has no persisted dataset available for rerun.",
    "dataset_not_found": "Persisted dataset was not found in DatasetRepository.",
    "internal_error": "Internal Generator API error occurred.",
}


def default_generator_fail(code: str, status: int, *, message: str | None = None):
    """Return a SecAgent-compatible structured, secret-free JSON error response."""
    base_code = code.split(":", 1)[0]
    safe_msg = message or _GENERATOR_ERROR_MESSAGES.get(code) or _GENERATOR_ERROR_MESSAGES.get(
        base_code, "Generator API request rejected."
    )
    return jsonify(
        workflow_schema_version="1.0.0",
        error={"code": code, "message": safe_msg},
    ), status


def register_generator_routes(app: Flask, ctx: GeneratorApiContext) -> None:
    """Register all G11.3C Generator API routes on a Flask app using injected dependencies."""
    fail_fn = ctx.fail or default_generator_fail
    skill_loader = ctx.skill_loader if ctx.skill_loader is not None else GeneratorSkillLoader()
    rate_limiter = _SlidingWindowRateLimiter(
        max_requests=ctx.rate_limit_max_generate_requests,
        window_seconds=ctx.rate_limit_window_seconds,
        clock=ctx.clock,
    )

    def _error(code: str, status: int, message: str | None = None):
        if ctx.fail is not None and message is None:
            return ctx.fail(code, status)
        return default_generator_fail(code, status, message=message)

    def _require_auth():
        if not ctx.operator_authorized():
            return _error("operator_authentication_required", 403)
        supplied = request.headers.get("X-SecAgent-Validation", "")
        if not supplied or not secrets.compare_digest(supplied, ctx.nonce):
            return _error("validation_nonce_required", 403)
        return None

    def _read_checked_json() -> tuple[dict[str, Any] | None, Any]:
        try:
            payload = _parse_strict_request_json(request.get_data(), max_bytes=ctx.max_body_bytes)
        except _StrictApiJsonError as exc:
            status = 413 if exc.code == "payload_too_large" else 400
            return None, _error(exc.code, status, exc.message)

        cred_err = detect_client_credential_or_endpoint_injection(payload)
        if cred_err is not None:
            return None, _error(cred_err, 400)

        if _contains_forbidden_authority_key(payload):
            return None, _error("authority_field_rejected", 400)

        return payload, None

    @app.get("/api/testing/generator/status")
    def generator_status():
        denied = _require_auth()
        if denied:
            return denied

        provider_status = ctx.generator_service._provider.status()  # local-only, zero network call
        skills_loaded: list[dict[str, Any]] = []
        skill_error: str | None = None
        try:
            for ident in skill_loader.list_profiles():
                skills_loaded.append(
                    {
                        "id": ident.id,
                        "version": ident.version,
                        "asi_code": ident.asi_code,
                        "asi_category": ident.asi_category,
                        "sha256": ident.sha256,
                    }
                )
        except GeneratorSkillError as exc:
            skill_error = exc.code

        judge_status = (
            ctx.orchestrator.judge_status()
            if ctx.orchestrator is not None and ctx.orchestrator.available
            else None
        )
        return jsonify(
            workflow_schema_version="1.0.0",
            provider=provider_status.model_dump(mode="json"),
            generate_and_run_available=bool(ctx.orchestrator is not None and ctx.orchestrator.available),
            judge=judge_status,
            supported_asi=list(SUPPORTED_ASI_CODES),
            limits={
                "min_per_asi": DEFAULT_MIN_PER_ASI,
                "default_per_asi": DEFAULT_PER_ASI,
                "max_per_asi": DEFAULT_MAX_PER_ASI,
                "max_total_cases": DEFAULT_MAX_TOTAL_CASES,
                "hard_max_per_asi": HARD_MAX_PER_ASI,
                "hard_max_total_cases": HARD_MAX_TOTAL_CASES,
            },
            defaults={
                "deduplicate_across_asi": GENERATOR_API_DEFAULT_DEDUPLICATE_ACROSS_ASI,
                "max_calls_per_asi": 1,
                "language": "en",
            },
            skills=skills_loaded,
            skill_error=skill_error,
        )

    @app.post("/api/testing/generator/readiness")
    def generator_readiness():
        denied = _require_auth()
        if denied:
            return denied

        payload, err = _read_checked_json()
        if err:
            return err
        assert payload is not None

        try:
            req = ReadinessApiRequest.model_validate(payload)
        except ValidationError:
            return _error("invalid_request", 400)

        report = assess_target_readiness(
            target_id=req.target_id,
            catalog=ctx.catalog,
            application_contexts=ctx.application_contexts,
            policy_store=ctx.policy_store,
            selected_asi=req.selected_asi,
            requested_scopes=req.requested_scopes or None,
            policy_ids_by_asi=req.policy_ids_by_asi or None,
        )
        if not report.target_exists:
            return _error("target_not_found", 404)

        return jsonify(
            workflow_schema_version="1.0.0",
            readiness=report.model_dump(mode="json"),
        )

    @app.post("/api/testing/generator/generate")
    def generator_generate():
        denied = _require_auth()
        if denied:
            return denied

        if not rate_limiter.allow():
            return _error("generator_rate_limited", 429)

        payload, err = _read_checked_json()
        if err:
            return err
        assert payload is not None

        try:
            api_req = GenerateApiRequest.model_validate(payload)
            service_req = api_req.to_service_request()
        except ValidationError:
            return _error("invalid_request", 400)

        # Fail fast with structured 503 if server provider credential is missing (R02).
        provider_status = ctx.generator_service._provider.status()
        if not provider_status.credential_available:
            return _error("generator_credential_unavailable", 503)

        try:
            result = ctx.generator_service.generate(service_req)
        except GenerationServiceError as exc:
            return _error(exc.code, 400, exc.message)

        if result.target_revision_sha256 is None:
            return _error("target_not_found", 404)

        # If every non-blocked ASI failed strictly due to credential missing, surface structured 503.
        non_blocked = [r for r in result.asi_results.values() if r.status != "blocked"]
        if non_blocked and all(
            r.provider_error_category == ProviderErrorCategory.CREDENTIAL_MISSING for r in non_blocked
        ):
            return _error("generator_credential_unavailable", 503)

        try:
            preview = ctx.preview_store.create_preview(
                result=result,
                owner_id=ctx.operator_identity(),
            )
        except PreviewStoreError as exc:
            return _error(exc.code, exc.status_code, exc.message)

        return jsonify(
            workflow_schema_version="1.0.0",
            preview=preview.model_dump(mode="json"),
        ), 201

    @app.get("/api/testing/generator/previews/<preview_id>")
    def generator_get_preview(preview_id: str):
        denied = _require_auth()
        if denied:
            return denied
        try:
            preview = ctx.preview_store.get_preview(
                preview_id=preview_id,
                owner_id=ctx.operator_identity(),
            )
        except PreviewStoreError as exc:
            return _error(exc.code, exc.status_code, exc.message)

        return jsonify(
            workflow_schema_version="1.0.0",
            preview=preview.model_dump(mode="json"),
        )

    @app.post("/api/testing/generator/previews/<preview_id>/edit")
    def generator_edit_preview(preview_id: str):
        denied = _require_auth()
        if denied:
            return denied

        payload, err = _read_checked_json()
        if err:
            return err
        assert payload is not None

        try:
            edit_req = PreviewEditRequest.model_validate(payload)
        except ValidationError:
            return _error("invalid_request", 400)

        try:
            preview = ctx.preview_store.update_preview(
                preview_id=preview_id,
                owner_id=ctx.operator_identity(),
                edit_request=edit_req,
            )
        except PreviewStoreError as exc:
            return _error(exc.code, exc.status_code, exc.message)

        return jsonify(
            workflow_schema_version="1.0.0",
            preview=preview.model_dump(mode="json"),
        )

    @app.post("/api/testing/generator/previews/<preview_id>/save")
    def generator_save_preview(preview_id: str):
        denied = _require_auth()
        if denied:
            return denied

        payload, err = _read_checked_json()
        if err:
            return err
        assert payload is not None

        try:
            save_req = PreviewSaveRequest.model_validate(payload)
        except ValidationError:
            return _error("invalid_request", 400)

        try:
            save_record = ctx.preview_store.save_preview(
                preview_id=preview_id,
                owner_id=ctx.operator_identity(),
                save_request=save_req,
                catalog=ctx.catalog,
                application_contexts=ctx.application_contexts,
                dataset_repo=ctx.dataset_repo,
                policy_store=ctx.policy_store,
            )
        except PreviewStoreError as exc:
            return _error(exc.code, exc.status_code, exc.message)

        status_code = 200 if save_record.idempotent_replay else 201
        return jsonify(
            workflow_schema_version="1.0.0",
            save_record=save_record.model_dump(mode="json"),
        ), status_code

    @app.get("/api/testing/generator/previews/<preview_id>/save-status")
    def generator_save_status(preview_id: str):
        denied = _require_auth()
        if denied:
            return denied
        try:
            status_payload = ctx.preview_store.get_save_status(
                preview_id=preview_id,
                owner_id=ctx.operator_identity(),
            )
        except PreviewStoreError as exc:
            return _error(exc.code, exc.status_code, exc.message)

        return jsonify(workflow_schema_version="1.0.0", **status_payload)

    @app.post("/api/testing/generator/generate-and-run")
    def generator_generate_and_run():
        denied = _require_auth()
        if denied:
            return denied

        if ctx.orchestrator is None or not ctx.orchestrator.available:
            return _error("generic_runner_unavailable", 503)

        if not rate_limiter.allow():
            return _error("generator_rate_limited", 429)

        payload, err = _read_checked_json()
        if err:
            return err
        assert payload is not None

        try:
            run_req = GenerateAndRunRequest.model_validate(payload)
        except ValidationError:
            return _error("invalid_request", 400)

        try:
            snapshot = ctx.orchestrator.start_workflow(
                req=run_req,
                owner_id=ctx.operator_identity(),
            )
        except OrchestrationError as exc:
            return _error(exc.code, exc.status_code, exc.message)

        if snapshot.idempotent_replay:
            status_code = 200
        elif snapshot.status == "running":
            status_code = 202
        else:
            status_code = 201
        return jsonify(
            workflow_schema_version="1.0.0",
            workflow=snapshot.model_dump(mode="json"),
        ), status_code

    @app.get("/api/testing/generator/generate-and-run/<workflow_id>")
    def generator_get_generate_and_run(workflow_id: str):
        denied = _require_auth()
        if denied:
            return denied

        if ctx.orchestrator is None:
            return _error("generic_runner_unavailable", 503)

        try:
            snapshot = ctx.orchestrator.get_workflow(
                workflow_id=workflow_id,
                owner_id=ctx.operator_identity(),
            )
        except OrchestrationError as exc:
            return _error(exc.code, exc.status_code, exc.message)

        return jsonify(
            workflow_schema_version="1.0.0",
            workflow=snapshot.model_dump(mode="json"),
        )

    @app.get("/api/testing/generator/generate-and-run/submission/<submission_id>")
    def generator_get_generate_and_run_by_submission(submission_id: str):
        denied = _require_auth()
        if denied:
            return denied

        if ctx.orchestrator is None:
            return _error("generic_runner_unavailable", 503)

        try:
            snapshot = ctx.orchestrator.get_workflow_by_submission(
                submission_id=submission_id,
                owner_id=ctx.operator_identity(),
            )
        except OrchestrationError as exc:
            return _error(exc.code, exc.status_code, exc.message)

        return jsonify(
            workflow_schema_version="1.0.0",
            workflow=snapshot.model_dump(mode="json"),
        )

    @app.post("/api/testing/generator/generate-and-run/<workflow_id>/rerun")
    def generator_rerun_generate_and_run(workflow_id: str):
        denied = _require_auth()
        if denied:
            return denied

        if ctx.orchestrator is None or not ctx.orchestrator.available:
            return _error("generic_runner_unavailable", 503)

        payload, err = _read_checked_json()
        if err:
            return err
        assert payload is not None

        try:
            rerun_req = GenerateAndRunRerunRequest.model_validate(payload)
        except ValidationError:
            return _error("invalid_request", 400)

        try:
            result_payload = ctx.orchestrator.rerun_workflow(
                workflow_id=workflow_id,
                owner_id=ctx.operator_identity(),
                rerun_req=rerun_req,
            )
        except OrchestrationError as exc:
            return _error(exc.code, exc.status_code, exc.message)

        status_code = 202 if rerun_req.async_execution else 201
        return jsonify(
            workflow_schema_version="1.0.0",
            **result_payload,
        ), status_code


def create_standalone_generator_app(
    *,
    generator_service: GeneratorService,
    dataset_repo: DatasetRepository,
    catalog: Any,
    application_contexts: Any | None,
    policy_store: Any | None = None,
    preview_store: GeneratorPreviewStore | None = None,
    operator_secret: str | None = None,
    additional_operator_secrets: Mapping[str, str] | None = None,
    local_single_user: bool = False,
    port: int = 8092,
    max_body_bytes: int = DEFAULT_GENERATOR_MAX_BODY_BYTES,
    rate_limit_max_generate_requests: int = DEFAULT_GENERATE_RATE_LIMIT_MAX,
    rate_limit_window_seconds: float = DEFAULT_GENERATE_RATE_LIMIT_WINDOW_SECONDS,
    clock: Callable[[], float] | None = None,
) -> tuple[Flask, GeneratorApiContext]:
    """Create an isolated Flask test harness enforcing SecAgent's exact HTTP security boundary.

    Does NOT modify or depend on `workflow/api.py`. Mirrors `workflow/api.py`'s loopback,
    Host, Origin, Sec-Fetch-Site, query-string, Transfer-Encoding, JSON-only, validation-nonce,
    and operator authentication checks so G11.3C can be verified end-to-end in isolation.
    """
    if not local_single_user and (not isinstance(operator_secret, str) or len(operator_secret) < 32):
        raise ValueError("Authenticated mode requires an operator_secret of at least 32 characters.")

    app = Flask(__name__, static_folder=None)
    app.config.update(MAX_CONTENT_LENGTH=max_body_bytes, DEBUG=False, PROPAGATE_EXCEPTIONS=False)
    nonce = secrets.token_urlsafe(32)
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    store = preview_store if preview_store is not None else GeneratorPreviewStore(clock=clock)

    valid_tokens: dict[str, str] = {}
    if operator_secret:
        valid_tokens["primary-operator"] = operator_secret
    if additional_operator_secrets:
        for label, tok in additional_operator_secrets.items():
            if isinstance(tok, str) and len(tok) >= 32:
                valid_tokens[label] = tok

    def _match_operator_label() -> str | None:
        if local_single_user:
            session_hdr = request.headers.get("X-SecAgent-Session", "").strip()
            return f"local-single-user:{session_hdr or 'default'}"
        supplied = request.headers.get("X-SecAgent-Operator", "")
        if not supplied:
            return None
        for label, expected in valid_tokens.items():
            if secrets.compare_digest(supplied, expected):
                return label
        return None

    def operator_authorized() -> bool:
        return _match_operator_label() is not None

    def operator_identity() -> str:
        label = _match_operator_label()
        if label is None:
            return ""
        return sha256(f"secagent-op:{label}".encode("utf-8")).hexdigest()

    @app.before_request
    def boundary():
        try:
            is_loopback = ipaddress.ip_address(request.remote_addr or "").is_loopback
        except ValueError:
            is_loopback = False
        if not is_loopback or request.host not in allowed_hosts:
            return default_generator_fail("local_only", 403)
        origin = request.headers.get("Origin")
        if origin not in {None, "http://" + request.host} or request.headers.get("Sec-Fetch-Site") == "cross-site":
            return default_generator_fail("origin_rejected", 403)
        if request.query_string or request.headers.get("Transfer-Encoding"):
            return default_generator_fail("invalid_request", 400)

        allowed_method = GENERATOR_EXACT_ROUTES.get(request.path)
        if allowed_method is None:
            for pattern, method in GENERATOR_REGEX_ROUTES:
                if re.fullmatch(pattern, request.path):
                    allowed_method = method
                    break
        if allowed_method is None:
            return default_generator_fail("not_found", 404)
        if request.method != allowed_method:
            return default_generator_fail("method_not_allowed", 405)
        if request.method == "GET" and request.content_length:
            return default_generator_fail("body_not_allowed", 400)
        if request.content_length and request.content_length > max_body_bytes:
            return default_generator_fail("payload_too_large", 413)
        if request.method == "POST":
            if origin != "http://" + request.host:
                return default_generator_fail("origin_required", 403)
            if request.mimetype != "application/json":
                return default_generator_fail("json_required", 415)
            supplied_nonce = request.headers.get("X-SecAgent-Validation", "")
            if not re.fullmatch(r"[A-Za-z0-9_-]{43}", supplied_nonce) or not secrets.compare_digest(
                supplied_nonce, nonce
            ):
                return default_generator_fail("validation_nonce_required", 403)
        return None

    @app.after_request
    def security_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.errorhandler(Exception)
    def handle_error(exc: Exception):
        if isinstance(exc, HTTPException):
            code = "payload_too_large" if exc.code == 413 else "invalid_request"
            return default_generator_fail(code, exc.code or 400)
        return default_generator_fail("internal_error", 500)

    ctx = GeneratorApiContext(
        generator_service=generator_service,
        preview_store=store,
        dataset_repo=dataset_repo,
        catalog=catalog,
        application_contexts=application_contexts,
        policy_store=policy_store,
        nonce=nonce,
        operator_authorized=operator_authorized,
        operator_identity=operator_identity,
        max_body_bytes=max_body_bytes,
        rate_limit_max_generate_requests=rate_limit_max_generate_requests,
        rate_limit_window_seconds=rate_limit_window_seconds,
        clock=clock,
    )
    register_generator_routes(app, ctx)
    return app, ctx
