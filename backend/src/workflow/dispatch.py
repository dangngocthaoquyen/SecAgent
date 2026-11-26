"""Bounded HTTP isolation, output sanitization, and controlled workflow dispatcher state."""

import json
from pathlib import Path
import re
import secrets
from threading import RLock
from time import perf_counter

import httpx

from reporting.redaction import Redactor
from testing import RunnerEvaluationConfig
from tools.http import HttpClientError, HttpResponse
from workflow.catalog import ROOT


class DispatchRejected(ValueError):
    """A controlled run cannot be admitted."""


class OneRequestHttpClient:
    """Enforce the exact URL, method, one request, deadline and response cap."""

    def __init__(self, endpoint: str, timeout: int, *, transport=None, max_bytes=65536,
                 stage_sink=None, before_request=None):
        self.endpoint, self.timeout = endpoint, timeout
        self.transport, self.max_bytes = transport, max_bytes
        self.stage_sink = stage_sink
        self.before_request = before_request
        self.used = 0

    def request(self, *, method, url, headers=None, json_body=None, timeout=None):
        if self.used or method != "POST" or url != self.endpoint or timeout != self.timeout:
            raise HttpClientError("Bounded target request rejected.")
        if self.before_request is None:
            self.used += 1  # Reserve before any transport activity; never retry.
        started = perf_counter()
        try:
            with httpx.Client(transport=self.transport, follow_redirects=False, trust_env=False) as client:
                if self.stage_sink is not None:
                    self.stage_sink("sending_target_request")
                if self.before_request is not None:
                    self.before_request()  # Last admission/cancellation gate, before transport.
                    self.used += 1
                with client.stream("POST", self.endpoint, headers=headers, json=json_body,
                        timeout=httpx.Timeout(connect=min(self.timeout, 3), read=self.timeout,
                                              write=min(self.timeout, 3), pool=min(self.timeout, 3))) as response:
                    if self.stage_sink is not None:
                        self.stage_sink("waiting_for_target_response")
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
                        duration_ms=(perf_counter() - started) * 1000, body_complete=True)
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
    """Shared operator secret, output-directory boundary, and run-lock controller."""

    def __init__(self, catalog, policy, output_root: Path, *, operator_secret: str,
                 transport=None, repository_root=ROOT, output_boundary=None,
                 hybrid_config: RunnerEvaluationConfig | None = None,
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
        self._lock = RLock()
        self._active = False

    def authorized(self, supplied: str) -> bool:
        return bool(supplied) and secrets.compare_digest(supplied, self.operator_secret)
