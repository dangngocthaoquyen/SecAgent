"""Minimal Garak CLI provider."""

import glob
import subprocess
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from integrations.security_tools.base import SecurityToolProvider
from integrations.security_tools.models import ExternalToolResult


class GarakRunConfig(BaseModel):
    """Configuration for one Garak CLI run."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    target_type: str = Field(min_length=1)
    spec: str = Field(min_length=1)
    generations: int = Field(default=1, ge=1)
    report_prefix: str | None = Field(default=None, min_length=1)
    timeout_seconds: float = Field(gt=0, allow_inf_nan=False)

    @field_validator("report_prefix")
    @classmethod
    def report_prefix_must_name_a_file_prefix(
        cls,
        value: str | None,
    ) -> str | None:
        if value is not None and Path(value).name in {"", ".", ".."}:
            raise ValueError("Garak report_prefix must name a file prefix.")
        return value


class GarakProvider(SecurityToolProvider):
    """Invoke Garak through its CLI and normalize the process result."""

    def __init__(
        self,
        *,
        executable: str | Path,
        config: GarakRunConfig,
    ) -> None:
        self._executable = str(executable)
        self._config = config

    def run(self) -> ExternalToolResult:
        """Run Garak once with the configured target and scan selection."""

        command = self._command()
        metadata = self._metadata()

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self._config.timeout_seconds,
                check=False,
                shell=False,
            )
        except FileNotFoundError:
            return ExternalToolResult(
                tool_name="garak",
                success=False,
                error=f"Garak executable not found: {self._executable}",
                metadata=metadata,
            )
        except subprocess.TimeoutExpired as exc:
            return ExternalToolResult(
                tool_name="garak",
                success=False,
                stdout=self._stream_text(exc.stdout),
                stderr=self._stream_text(exc.stderr),
                error=(
                    "Garak execution timed out after "
                    f"{self._config.timeout_seconds} seconds."
                ),
                artifacts=self._discover_artifacts(),
                metadata=metadata,
            )
        except OSError as exc:
            return ExternalToolResult(
                tool_name="garak",
                success=False,
                error=f"Failed to start Garak: {exc}",
                metadata=metadata,
            )

        success = completed.returncode == 0
        return ExternalToolResult(
            tool_name="garak",
            success=success,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            error=None if success else f"Garak exited with code {completed.returncode}.",
            artifacts=self._discover_artifacts(),
            metadata=metadata,
        )

    def _command(self) -> list[str]:
        command = [
            self._executable,
            "--target_type",
            self._config.target_type,
            "--spec",
            self._config.spec,
            "--generations",
            str(self._config.generations),
        ]
        if self._config.report_prefix is not None:
            command.extend(["--report_prefix", self._config.report_prefix])
        return command

    def _metadata(self) -> dict[str, Any]:
        return {
            "target_type": self._config.target_type,
            "spec": self._config.spec,
            "generations": self._config.generations,
            "report_prefix": self._config.report_prefix,
        }

    def _discover_artifacts(self) -> list[str]:
        if self._config.report_prefix is None:
            return []

        prefix = Path(self._config.report_prefix)
        pattern = f"{glob.escape(prefix.name)}*"
        return sorted(
            str(path.resolve())
            for path in prefix.parent.glob(pattern)
            if path.is_file()
        )

    @staticmethod
    def _stream_text(value: str | bytes | None) -> str | None:
        if isinstance(value, bytes):
            return value.decode(errors="replace")
        return value
