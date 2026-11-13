"""One explicitly authorized native Runner dispatch per workflow process."""

from datetime import datetime, timezone
from contextlib import nullcontext
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import secrets
from threading import Lock
from time import perf_counter
from uuid import uuid4

import httpx

from backend.scripts.run_native_smoke import run_smoke
from reporting.redaction import Redactor
from targets.adapters.http_adapter import HttpTargetAdapter
from testing import Executor, RunnerEvaluationConfig
from tools.http import HttpClientError, HttpResponse
from workflow.admission import AdmissionRequest, AdmissionService
from workflow.catalog import make_profile
from workflow.fixture_runtime import LocalMockFixtureRuntime
from workflow.plans import ROOT, safe_file


class DispatchRejected(ValueError):
    """A controlled run cannot be admitted."""


class OneRequestHttpClient:
    """Enforce the exact URL, method, one request, deadline and response cap."""

    def __init__(self, endpoint: str, timeout: int, *, transport=None, max_bytes=65536):
        self.endpoint, self.timeout = endpoint, timeout
        self.transport, self.max_bytes = transport, max_bytes
        self.used = 0

    def request(self, *, method, url, headers=None, json_body=None, timeout=None):
        if self.used or method != "POST" or url != self.endpoint or timeout != self.timeout:
            raise HttpClientError("Bounded target request rejected.")
        self.used += 1  # Reserve before any transport activity; never retry.
        started = perf_counter()
        try:
            with httpx.Client(transport=self.transport, follow_redirects=False, trust_env=False) as client:
                with client.stream("POST", self.endpoint, headers=headers, json=json_body,
                        timeout=httpx.Timeout(connect=min(self.timeout, 3), read=self.timeout,
                                              write=min(self.timeout, 3), pool=min(self.timeout, 3))) as response:
                    if int(response.headers.get("content-length", "0")) > self.max_bytes:
                        raise HttpClientError("Target response exceeded size limit.")
                    chunks, size = [], 0
                    for chunk in response.iter_bytes():
                        size += len(chunk)
                        if size > self.max_bytes:
                            raise HttpClientError("Target response exceeded size limit.")
                        if perf_counter() - started > self.timeout:
                            raise HttpClientError("Target request exceeded time limit.")
                        chunks.append(chunk)
                    raw = b"".join(chunks)
                    # Only body fields needed by the existing adapter are retained.
                    value = None
                    try:
                        value = json.loads(raw.decode("utf-8"))
                    except (ValueError, UnicodeError):
                        pass
                    return HttpResponse(status_code=response.status_code,
                        headers={}, text=raw.decode("utf-8", errors="replace"), json_body=value,
                        duration_ms=(perf_counter() - started) * 1000)
        except (httpx.RequestError, httpx.TimeoutException) as exc:
            raise HttpClientError("Target request failed or timed out.",
                duration_ms=(perf_counter() - started) * 1000) from exc


def sanitized(value, *, secrets_to_remove=(), field=None):
    cleaner = Redactor(secrets_to_remove)
    if isinstance(value, str):
        # Schema digests are integrity metadata, not opaque runtime tokens.
        # Preserve only well-formed digest fields after secret redaction.
        digest = isinstance(field, str) and field.endswith("sha256") and re.fullmatch(r"[a-f0-9]{64}", value)
        return cleaner.clean(value, limit=65536, opaque=not digest)
    if isinstance(value, dict):
        return {key: sanitized(item, secrets_to_remove=secrets_to_remove, field=key) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitized(item, secrets_to_remove=secrets_to_remove) for item in value]
    return value


class ControlledDispatcher:
    """Sequential, single-use-plan native Runner dispatch with trusted bindings."""

    def __init__(self, catalog, policy, output_root: Path, *, operator_secret: str,
                 transport=None, repository_root=ROOT, output_boundary=None,
                 fixture_runtime=None, hybrid_config: RunnerEvaluationConfig | None = None,
                 judge_provider=None):
        if not isinstance(operator_secret, str) or len(operator_secret) < 32:
            raise ValueError("A separate operator secret of at least 32 characters is required.")
        self.catalog, self.policy = catalog, policy
        self.repository_root = Path(repository_root).resolve()
        self.output_root = Path(output_root).absolute()
        results_root = (Path(output_boundary).resolve() if output_boundary is not None
                        else self.repository_root / "results")
        if not self.output_root.is_relative_to(results_root) or self.output_root == results_root:
            raise ValueError("Controlled outputs must be below the selected workspace results directory.")
        for ancestor in (self.output_root, *self.output_root.parents):
            if ancestor == results_root.parent:
                break
            if ancestor.is_symlink():
                raise ValueError("Linked result directories are unsupported.")
        self.output_root.mkdir(parents=True, exist_ok=True)
        self.operator_secret = operator_secret
        self.transport = transport
        if hybrid_config is not None:
            if (hybrid_config.mode != "hybrid" or not hybrid_config.judge_enabled
                    or hybrid_config.max_judge_calls != 1
                    or (judge_provider is None and (not hybrid_config.allow_live_judge or hybrid_config.pi is None))
                    or (judge_provider is not None and not isinstance(transport, httpx.MockTransport))):
                raise ValueError("Web hybrid Judge requires a bounded server-owned configuration.")
        elif judge_provider is not None:
            raise ValueError("A web Judge provider requires hybrid configuration.")
        self.hybrid_config, self.judge_provider = hybrid_config, judge_provider
        if fixture_runtime is not None and (transport is None or not isinstance(fixture_runtime, LocalMockFixtureRuntime)):
            raise ValueError("GH-WEB-001 fixture dispatch is limited to local synthetic mock transport.")
        self.fixture_runtime = fixture_runtime
        self._lock = Lock()
        self._active = False
        self._claimed_keys = set()

    def authorized(self, supplied: str) -> bool:
        return bool(supplied) and secrets.compare_digest(supplied, self.operator_secret)

    def _admission(self, selection: AdmissionRequest):
        service = AdmissionService(self.catalog, self.policy, root=self.repository_root,
                                   hybrid_config=self.hybrid_config)
        # Server-owned concrete path: one reviewed HTTP adapter, observer and
        # native report writer. The case still needs a matching operator grant.
        case_id = selection.testcase_ids[0] if len(selection.testcase_ids) == 1 else None
        wired = case_id == "GH-C01" or (case_id == "GH-WEB-001" and self.fixture_runtime is not None)
        if wired and selection.target.target_id in self.catalog._targets:
            initial = service.assess(selection)
            asset = initial["asset_sha256"].get(case_id)
            if asset:
                key = (selection.target.target_id, selection.target.profile_revision, case_id, asset)
                binding = {"protocol": "openai-chat", "response_observer": True,
                           "report_sink": True, "variables": {}, "environment": {}}
                if case_id == "GH-WEB-001":
                    binding.update(fresh_fixture_factory=True, collector_recording_executor=True,
                                   provenance="synthetic_mock")
                service.bindings[key] = binding
        return service

    def readiness(self, selection: AdmissionRequest, *, admit=False):
        result = self._admission(selection).assess(selection, admit=admit)
        key = self._available_claim_key(selection, result)
        result['dispatch_available'] = bool(result['admitted'] and not self._active and key)
        return result

    def _available_claim_key(self, selection, assessment):
        if not assessment.get("admitted"):
            return None
        case_id = selection.testcase_ids[0]
        asset = assessment["asset_sha256"].get(case_id)
        for grant in self.policy.grants:
            if (grant.target_id != selection.target.target_id
                    or grant.profile_revision != selection.target.profile_revision
                    or grant.policy_ref != selection.target.policy_ref
                    or grant.testcase_id != case_id or grant.asset_sha256 != asset
                    or grant.expires_at <= datetime.now(timezone.utc)):
                continue
            if case_id == "GH-WEB-001" and not grant.authorization_id:
                continue  # Web attempts require distinct server-owned grants.
            key = "auth-" + grant.authorization_id if grant.authorization_id else assessment["plan_id"]
            if key not in self._claimed_keys and not (self.output_root / ("claim-" + key)).exists():
                return key
        return None

    def run(self, selection: AdmissionRequest):
        with self._lock:
            if self._active:
                raise DispatchRejected("A controlled run is already active.")
            case_id = selection.testcase_ids[0] if len(selection.testcase_ids) == 1 else None
            if (case_id not in {"GH-C01", "GH-WEB-001"} or selection.asi_categories != ["ASI01"]
                    or (case_id == "GH-WEB-001" and self.fixture_runtime is None)):
                raise DispatchRejected("The selected ASI01 slice is not wired.")
            assessment = self.readiness(selection, admit=True)
            if not assessment["admitted"]:
                raise DispatchRejected("Target, assets, authorization or binding is not ready.")
            if not assessment["dispatch_available"]:
                raise DispatchRejected("This plan was already claimed or a run is active.")
            preset = self.catalog._targets[selection.target.target_id]
            profile = make_profile(preset, selection.target.model, selection.target.timeout_seconds,
                self.catalog._config.credential_aliases.get(preset.credential_alias))
            case_path = self.repository_root / "testcases" / "goal_hijacking" / (case_id + ".yaml")
            safe_file(case_path, self.repository_root)
            run_id = uuid4().hex
            claim_key = self._available_claim_key(selection, assessment)
            if claim_key is None:
                raise DispatchRejected("No fresh execution authorization remains.")
            claim_path = self.output_root / ("claim-" + claim_key)
            try:
                with claim_path.open("x", encoding="utf-8") as claim:
                    json.dump({"run_id": run_id, "claimed_at": datetime.now(timezone.utc).isoformat()}, claim)
            except FileExistsError:
                raise DispatchRejected("This execution authorization was already claimed.") from None
            self._claimed_keys.add(claim_key)
            self._active = True  # Plan claim persists across restarts, including failures.
            run_dir = self.output_root / run_id
            try:
                run_dir.mkdir(exist_ok=False)
            except OSError:
                self._active = False
                raise DispatchRejected("Run directory could not be created; claim remains consumed.") from None

        client = OneRequestHttpClient(preset.endpoint, selection.target.timeout_seconds,
                                      transport=self.transport)
        adapter = HttpTargetAdapter(http_client=client)
        credential_name = self.catalog._config.credential_aliases.get(preset.credential_alias)
        credential_value = os.environ.get(credential_name, '') if credential_name else ''
        redaction_values = tuple(value for value in (self.operator_secret, credential_value) if value)
        try:
            fixture_context = (self.fixture_runtime.open(run_dir, profile.id)
                               if case_id == "GH-WEB-001" else nullcontext(None))
            with fixture_context as fixture:
                evaluation_config = (self.hybrid_config if selection.evaluation_mode == "hybrid"
                                     else RunnerEvaluationConfig())
                report_path, summary = run_smoke(None, case_path, run_dir,
                    target_profile=profile, executor=Executor({"generic_http": adapter}),
                    evaluation_config=evaluation_config,
                    judge_provider=self.judge_provider if selection.evaluation_mode == "hybrid" else None,
                    web_fixture_run=fixture.directory if fixture else None,
                    source_provenance="synthetic_mock" if fixture else None,
                    sanitize_summary=lambda row: sanitized(row, secrets_to_remove=redaction_values))
            evidence_captured = False
            if fixture:
                manifest = fixture.directory / "manifest.json"
                events = fixture.directory / "events.jsonl"
                rows = fixture.rows()
                evidence_captured = bool(rows)
                provenance = {"source": "synthetic_mock", "run_id": run_id,
                    "native_execution_id": summary["evaluation"].get("run_id"),
                    "fixture_correlation_sha256": sha256(fixture.config["run_id"].encode()).hexdigest(),
                    "file_byte_sha256": {"fixture/manifest.json": sha256(manifest.read_bytes()).hexdigest(),
                                         **({"fixture/events.jsonl": sha256(events.read_bytes()).hexdigest()} if events.exists() else {})},
                    "page_events": sum(r["kind"] == "page" for r in rows),
                    "callback_events": sum(r["kind"] == "receipt" for r in rows),
                    "limitation": "Stored local mock logs are not remote action attestation."}
                with (run_dir / "artifact-provenance.json").open("x", encoding="utf-8") as stream:
                    json.dump(provenance, stream, sort_keys=True)
            if summary["evaluation"].get("report_fault") or summary["evaluation"].get("report_sink_fault"):
                raise RuntimeError("Native report was incomplete.")
            report_sha = sha256(report_path.read_bytes()).hexdigest()
            result = {"workflow_schema_version": "1.0.0", "run_id": run_id,
                "plan_id": assessment["plan_id"],
                "native_execution_id": summary["evaluation"].get("run_id"),
                "execution_status": "completed" if summary["smoke_execution_succeeded"] else "failed",
                "testcase_id": case_id, "target_id": profile.id,
                "target_request_count": client.used, "report_sha256": report_sha,
                "historical_verdict": summary["evaluation"]["final_verdict"],
                "evaluation_mode": summary["evaluation"].get("evaluation_mode"),
                "evidence_captured": evidence_captured,
                "artifact_provenance": "synthetic_mock" if fixture else "target_observation",
                "report_persisted": True, "reporting_snapshot_contains_run": False,
                "report_file": report_path.name,
                "reporting_run_reference": run_id,
                "reporting_view": "run/" + run_id,
                "limitation": "New native report is outside the startup snapshot; reporting requires explicit controlled-run root selection."}
            with (run_dir / "run-summary.json").open("x", encoding="utf-8") as stream:
                json.dump(result, stream, sort_keys=True)
            return result
        except Exception:
            # Keep the claim, directory and any partial diagnostic evidence.
            failure = {"workflow_schema_version": "1.0.0", "run_id": run_id,
                "plan_id": assessment["plan_id"], "native_execution_id": None,
                "execution_status": "failed", "testcase_id": case_id,
                "evaluation_mode": selection.evaluation_mode,
                "target_id": profile.id, "target_request_count": client.used,
                "evidence_captured": False,
                "artifact_provenance": "synthetic_mock" if case_id == "GH-WEB-001" else "target_observation",
                "report_persisted": False, "reporting_snapshot_contains_run": False,
                "limitation": "Run failed; review local operator logs without retrying automatically."}
            with (run_dir / "run-summary.json").open("x", encoding="utf-8") as stream:
                json.dump(failure, stream, sort_keys=True)
            return failure
        finally:
            with self._lock:
                self._active = False
