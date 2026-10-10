"""Stateless Pi CLI connector. No target verdict is produced on process failure."""

import os
import signal
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Protocol, Sequence

from pydantic import BaseModel, ConfigDict, Field

from integrations.external_evaluator.base import ExternalEvaluatorProvider
from integrations.external_evaluator.models import (
    EvaluationRequest, ExternalEvaluationOutcome, ProviderFault, ProviderFaultCode,
    SkillIdentity,
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


@dataclass(frozen=True)
class ProcessOutput:
    exit_code: int | None
    stdout: bytes = b""
    stderr: bytes = b""
    timed_out: bool = False
    output_exceeded: bool = False


class ProcessRunner(Protocol):
    def run(
        self, argv: Sequence[str], *, input_bytes: bytes, cwd: Path,
        env: Mapping[str, str], timeout_seconds: float, max_output_bytes: int,
    ) -> ProcessOutput: ...


class PiExecutableMissing(FileNotFoundError):
    """The configured process runner could not find Pi."""


class BoundedSubprocessRunner:
    """Drain both pipes while enforcing output and wall-clock limits."""

    def run(
        self, argv: Sequence[str], *, input_bytes: bytes, cwd: Path,
        env: Mapping[str, str], timeout_seconds: float, max_output_bytes: int,
    ) -> ProcessOutput:
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
        try:
            while process.poll() is None:
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
            timed_out=timed_out, output_exceeded=exceeded.is_set(),
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
    ) -> None:
        self._config = config
        self._bundle_loader = bundle_loader or SkillBundleLoader()
        self._process_runner = process_runner or BoundedSubprocessRunner()

    def evaluate(self, request: EvaluationRequest) -> ExternalEvaluationOutcome:
        started = time.monotonic()
        request_hash = request.sha256
        loaded_skill: SkillIdentity | None = None

        def fault(code: ProviderFaultCode, message: str, exit_code: int | None = None):
            return ExternalEvaluationOutcome(
                request_sha256=request_hash, skill=loaded_skill,
                fault=ProviderFault(code=code, message=message),
                duration_ms=(time.monotonic() - started) * 1000,
                exit_code=exit_code,
            )

        try:
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
        except OSError:
            return fault(ProviderFaultCode.PROCESS_ERROR, "Pi process or isolated workspace could not be started.")

        if process.timed_out:
            return fault(ProviderFaultCode.TIMEOUT, "Pi process timed out.", process.exit_code)
        if process.output_exceeded or len(process.stdout) > self._config.max_output_bytes or len(process.stderr) > self._config.max_output_bytes:
            return fault(ProviderFaultCode.OUTPUT_LIMIT, "Pi process output exceeded the limit.", process.exit_code)
        if process.exit_code != 0:
            return fault(ProviderFaultCode.NONZERO_EXIT, "Pi process exited unsuccessfully.", process.exit_code)
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
            env["PI_CODING_AGENT_DIR"] = str(workdir)
            argv = [
                self._config.executable, "--print", "--no-session", "--no-tools",
                "--no-extensions", "--no-skills", "--no-prompt-templates",
                "--no-themes", "--no-context-files", "--system-prompt",
                str(prompt_path), "--provider", self._config.provider,
                "--model", self._config.model,
            ]
            try:
                return self._process_runner.run(
                    argv, input_bytes=payload, cwd=workdir, env=env,
                    timeout_seconds=self._config.timeout_seconds,
                    max_output_bytes=self._config.max_output_bytes,
                )
            except FileNotFoundError as exc:
                raise PiExecutableMissing() from exc
