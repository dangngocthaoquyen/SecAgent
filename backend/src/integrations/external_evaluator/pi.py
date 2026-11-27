"""Stateless Pi CLI connector. No target verdict is produced on process failure."""

import inspect
import json
import os
import re
import signal
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Protocol, Sequence

from pydantic import BaseModel, ConfigDict, Field

from core.cancellation import RunCancelledError
from integrations.external_evaluator.base import ExternalEvaluatorProvider
from integrations.external_evaluator.models import (
    EvaluationRequest, ExternalEvaluationOutcome, ProviderFault, ProviderFaultCode,
    ProcessDiagnosticCode, SkillIdentity,
)
from integrations.external_evaluator.skills import SkillBundleError, SkillBundleLoader
from integrations.external_evaluator.validation import JudgeOutputError, parse_judge_response


class PiEvaluatorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    executable: str = Field(min_length=1)
    model: str = Field(min_length=1)
    provider: str = Field(min_length=1)
    timeout_seconds: float = Field(gt=0, allow_inf_nan=False)
    max_output_bytes: int = Field(default=65536, gt=0)
    credential_env: tuple[str, ...] = ()
    use_pi_auth_file: bool = False


@dataclass(frozen=True)
class ProcessOutput:
    exit_code: int | None
    stdout: bytes = b""
    stderr: bytes = b""
    timed_out: bool = False
    output_exceeded: bool = False
    cancelled: bool = False


class ProcessRunner(Protocol):
    def run(
        self, argv: Sequence[str], *, input_bytes: bytes, cwd: Path,
        env: Mapping[str, str], timeout_seconds: float, max_output_bytes: int,
    ) -> ProcessOutput: ...


class PiExecutableMissing(FileNotFoundError):
    """The configured process runner could not find Pi."""


class PiAuthUnavailable(RuntimeError):
    """Configured Pi auth.json file or provider entry is missing or malformed."""


def _classify_nonzero_stderr(stderr: bytes, provider: str, model: str) -> ProcessDiagnosticCode:
    """Classify only a known first error line; never return process text."""
    first = next((line.strip() for line in stderr[:2048].decode("utf-8", errors="replace").splitlines()
                  if line.strip()), "")
    first = re.sub(r"\x1b\[[0-9;]*m", "", first).strip()
    if first == f"No API key found for {provider}.":
        return ProcessDiagnosticCode.CREDENTIAL_MISSING
    if re.match(r"^(?:API Error: (?:HTTP )?|Error: HTTP |HTTP )(?:401|403)\b", first):
        return ProcessDiagnosticCode.AUTH_REJECTED
    if first == f'Model "{provider}/{model}" not found. Use --list-models to see available models.':
        return ProcessDiagnosticCode.MODEL_REJECTED
    if re.match(r"^(?:Error: )?(?:fetch failed|connect E(?:CONNREFUSED|CONNRESET|HOSTUNREACH|NETUNREACH)\b|getaddrinfo E(?:NOTFOUND|AI_AGAIN)\b|network error\b)", first, re.IGNORECASE):
        return ProcessDiagnosticCode.NETWORK_ERROR
    if re.match(r"^(?:Error: )?(?:Cannot find module\b|Unknown option:\s|SyntaxError:\s|\[ERR_MODULE_NOT_FOUND\])", first):
        return ProcessDiagnosticCode.STARTUP_ERROR
    return ProcessDiagnosticCode.UNKNOWN


class BoundedSubprocessRunner:
    """Drain both pipes while enforcing output and wall-clock limits."""

    def run(
        self, argv: Sequence[str], *, input_bytes: bytes, cwd: Path,
        env: Mapping[str, str], timeout_seconds: float, max_output_bytes: int,
        cancel_event: threading.Event | None = None,
    ) -> ProcessOutput:
        if cancel_event is not None and cancel_event.is_set():
            return ProcessOutput(exit_code=None, cancelled=True)
        process = subprocess.Popen(
            list(argv), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, cwd=cwd, env=dict(env), shell=False,
            start_new_session=os.name != "nt",
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
        )
        stdout, stderr = bytearray(), bytearray()
        exceeded = threading.Event()

        def drain(pipe, sink: bytearray) -> None:
            with pipe:
                while chunk := pipe.read(4096):
                    remaining = max_output_bytes + 1 - len(sink)
                    if remaining > 0:
                        sink.extend(chunk[:remaining])
                    if len(sink) > max_output_bytes:
                        exceeded.set()

        def write_input() -> None:
            try:
                with process.stdin:
                    process.stdin.write(input_bytes)
            except (BrokenPipeError, OSError):
                pass

        threads = [
            threading.Thread(target=drain, args=(process.stdout, stdout), daemon=True),
            threading.Thread(target=drain, args=(process.stderr, stderr), daemon=True),
            threading.Thread(target=write_input, daemon=True),
        ]
        for thread in threads:
            thread.start()
        deadline = time.monotonic() + timeout_seconds
        timed_out = False
        cancelled = False
        try:
            while process.poll() is None:
                if cancel_event is not None and cancel_event.is_set():
                    cancelled = True
                    self._stop(process)
                    break
                if exceeded.is_set():
                    self._stop(process)
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    self._stop(process)
                    break
                time.sleep(0.02)
            process.wait()
        finally:
            if process.poll() is None:
                self._stop(process)
            for thread in threads:
                thread.join(timeout=1)
        return ProcessOutput(
            exit_code=process.returncode, stdout=bytes(stdout), stderr=bytes(stderr),
            timed_out=timed_out, output_exceeded=exceeded.is_set(), cancelled=cancelled,
        )

    @staticmethod
    def _stop(process: subprocess.Popen) -> None:
        if process.poll() is not None:
            return
        if os.name == "nt":
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=5, check=False, shell=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                pass
            if process.poll() is None:
                process.kill()
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


class PiEvaluatorProvider(ExternalEvaluatorProvider):
    def __init__(
        self, config: PiEvaluatorConfig, *,
        bundle_loader: SkillBundleLoader | None = None,
        process_runner: ProcessRunner | None = None,
        cancel_event: threading.Event | None = None,
    ) -> None:
        self._config = config
        self._bundle_loader = bundle_loader or SkillBundleLoader()
        self._process_runner = process_runner or BoundedSubprocessRunner()
        self._cancel_event = cancel_event

    def evaluate(self, request: EvaluationRequest) -> ExternalEvaluationOutcome:
        if self._cancel_event is not None and self._cancel_event.is_set():
            raise RunCancelledError("judge_cancelled_before_invocation")
        started = time.monotonic()
        request_hash = request.sha256
        loaded_skill: SkillIdentity | None = None

        def fault(code: ProviderFaultCode, message: str, exit_code: int | None = None,
                  diagnostic_code: ProcessDiagnosticCode | None = None):
            return ExternalEvaluationOutcome(
                request_sha256=request_hash, skill=loaded_skill,
                fault=ProviderFault(code=code, message=message, diagnostic_code=diagnostic_code),
                duration_ms=(time.monotonic() - started) * 1000,
                exit_code=exit_code,
            )

        try:
            scope = request.trusted_context.get("evaluation_scope")
            if request.evaluation_type == "tool_misuse" and scope == "tool_intent_response":
                bundle = self._bundle_loader.load(request.evaluation_type, evaluation_scope=scope)
            else:
                bundle = self._bundle_loader.load(request.evaluation_type)
        except SkillBundleError:
            return fault(ProviderFaultCode.SKILL_UNAVAILABLE, "Trusted skill bundle unavailable.")
        loaded_skill = bundle.identity
        if loaded_skill != request.skill:
            return fault(ProviderFaultCode.SKILL_MISMATCH, "Request skill identity differs from the loaded bundle.")

        payload = request.model_dump_json().encode("utf-8")
        try:
            process = self._invoke(bundle.system_prompt, payload)
        except PiExecutableMissing:
            return fault(ProviderFaultCode.EXECUTABLE_MISSING, "Pi executable not found.")
        except PiAuthUnavailable:
            return fault(
                ProviderFaultCode.NONZERO_EXIT,
                "Configured Pi provider authentication is unavailable.",
                diagnostic_code=ProcessDiagnosticCode.CREDENTIAL_MISSING,
            )
        except OSError:
            return fault(ProviderFaultCode.PROCESS_ERROR, "Pi process or isolated workspace could not be started.")

        if process.cancelled or (self._cancel_event is not None and self._cancel_event.is_set()):
            raise RunCancelledError("judge_cancelled")
        if process.timed_out:
            return fault(ProviderFaultCode.TIMEOUT, "Pi process timed out.", process.exit_code)
        if process.output_exceeded or len(process.stdout) > self._config.max_output_bytes or len(process.stderr) > self._config.max_output_bytes:
            return fault(ProviderFaultCode.OUTPUT_LIMIT, "Pi process output exceeded the limit.", process.exit_code)
        if process.exit_code != 0:
            return fault(ProviderFaultCode.NONZERO_EXIT, "Pi process exited unsuccessfully.",
                process.exit_code, _classify_nonzero_stderr(
                    process.stderr, self._config.provider, self._config.model))
        try:
            result = parse_judge_response(process.stdout.decode("utf-8"), request)
        except (UnicodeDecodeError, JudgeOutputError):
            return fault(ProviderFaultCode.INVALID_OUTPUT, "Pi output failed Judge contract validation.", process.exit_code)
        return ExternalEvaluationOutcome(
            request_sha256=request_hash, skill=loaded_skill, result=result,
            duration_ms=(time.monotonic() - started) * 1000,
            exit_code=process.exit_code,
        )

    def _invoke(self, system_prompt: str, payload: bytes) -> ProcessOutput:
        with tempfile.TemporaryDirectory(prefix="secagent-judge-") as temporary:
            workdir = Path(temporary)
            prompt_path = workdir / "trusted-system.md"
            prompt_path.write_text(system_prompt, encoding="utf-8")
            env_keys = (
                "PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP",
                *self._config.credential_env,
            )
            env = {key: os.environ[key] for key in env_keys if key in os.environ}
            temp_auth: Path | None = None
            if self._config.use_pi_auth_file:
                auth_path = Path.home() / ".pi" / "agent" / "auth.json"
                has_env_cred = any(env.get(name) for name in self._config.credential_env)
                if not auth_path.is_file():
                    if not has_env_cred:
                        raise PiAuthUnavailable("Pi auth.json not found.")
                else:
                    try:
                        auth_obj = json.loads(auth_path.read_text(encoding="utf-8-sig"))
                    except (OSError, UnicodeError, ValueError) as exc:
                        if not has_env_cred:
                            raise PiAuthUnavailable("Pi auth.json unreadable or invalid JSON.") from exc
                        auth_obj = None
                    if isinstance(auth_obj, dict) and self._config.provider in auth_obj:
                        temp_auth = workdir / "auth.json"
                        payload_auth = json.dumps(
                            {self._config.provider: auth_obj[self._config.provider]}
                        ).encode("utf-8")
                        fd = os.open(temp_auth, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                        try:
                            with os.fdopen(fd, "wb") as stream:
                                stream.write(payload_auth)
                        except Exception:
                            try:
                                temp_auth.unlink(missing_ok=True)
                            except OSError:
                                pass
                            raise
                        if os.name != "nt":
                            os.chmod(temp_auth, 0o600)
                    elif not has_env_cred:
                        raise PiAuthUnavailable("Provider entry absent from Pi auth.json.")
            env["PI_CODING_AGENT_DIR"] = str(workdir)
            argv = [
                self._config.executable, "--print", "--no-session", "--no-tools",
                "--no-extensions", "--no-skills", "--no-prompt-templates",
                "--no-themes", "--no-context-files", "--system-prompt",
                str(prompt_path), "--provider", self._config.provider,
                "--model", self._config.model,
            ]
            try:
                run_kwargs: dict[str, object] = {
                    "input_bytes": payload,
                    "cwd": workdir,
                    "env": env,
                    "timeout_seconds": self._config.timeout_seconds,
                    "max_output_bytes": self._config.max_output_bytes,
                }
                if self._cancel_event is not None:
                    try:
                        sig = inspect.signature(self._process_runner.run)
                        if "cancel_event" in sig.parameters or any(
                            p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
                        ):
                            run_kwargs["cancel_event"] = self._cancel_event
                    except (TypeError, ValueError):
                        pass
                return self._process_runner.run(argv, **run_kwargs)
            except FileNotFoundError as exc:
                raise PiExecutableMissing() from exc
            finally:
                if temp_auth is not None:
                    try:
                        temp_auth.unlink(missing_ok=True)
                    except OSError:
                        pass
