"""Load only the trusted Markdown files selected by an allowlisted type."""

from dataclasses import dataclass
import hashlib
from pathlib import Path

from integrations.external_evaluator.identity import SKILLS, skill_identity
from integrations.external_evaluator.models import EvaluationType, SkillIdentity

RESPONSE_FIRST_SKILLS = SKILLS.parent / "response_first"
RESPONSE_SCOPE_RUBRICS = {
    ("tool_misuse", "tool_intent_response"): "tool-misuse-response.md",
}


RUBRICS = {
    "goal_hijacking": "goal-hijacking.md",
    "prompt_injection": "prompt-injection.md",
    "tool_misuse": "tool-misuse.md",
    "sensitive_data_disclosure": "sensitive-data-disclosure.md",
    "identity_privilege_abuse": "identity-privilege-abuse.md",
    "unexpected_code_execution": "unexpected-code-execution-response.md",
}
SHARED = ("SKILL.md", "verdict-policy.md", "untrusted-content-policy.md")


class SkillBundleError(ValueError):
    """The trusted skill bundle is absent, invalid, or unreadable."""


@dataclass(frozen=True)
class SkillBundle:
    identity: SkillIdentity
    system_prompt: str


class SkillBundleLoader:
    def __init__(self, root: Path = SKILLS) -> None:
        self._root = Path(root)

    def load(
        self,
        evaluation_type: EvaluationType,
        *,
        evaluation_scope: str | None = None,
    ) -> SkillBundle:
        if evaluation_type not in RUBRICS:
            raise SkillBundleError("Unsupported evaluation type.")
        root = self._root.resolve()
        if (evaluation_type, evaluation_scope) in RESPONSE_SCOPE_RUBRICS:
            rubric_name = RESPONSE_SCOPE_RUBRICS[(evaluation_type, evaluation_scope)]
            resp_root = (
                self._root.parent / "response_first"
                if (self._root.parent / "response_first").is_dir()
                else RESPONSE_FIRST_SKILLS
            ).resolve()
            rubric_path = (resp_root / rubric_name).resolve()
            try:
                if not rubric_path.is_relative_to(resp_root) or not rubric_path.is_file():
                    raise SkillBundleError(f"Required response-first rubric unavailable: {rubric_name}.")
                parts = []
                digest = hashlib.sha256()
                for relative in SHARED:
                    path = self._root / relative
                    if not path.resolve().is_relative_to(root) or not path.is_file():
                        raise SkillBundleError(f"Required trusted skill file is unavailable: {relative}.")
                    raw = path.read_bytes()
                    digest.update(relative.encode("utf-8") + b"\0" + raw + b"\0")
                    parts.append(f"# Trusted skill file: {relative}\n\n{raw.decode('utf-8')}")
                rf_raw = rubric_path.read_bytes()
                digest.update(f"response_first/{rubric_name}".encode("utf-8") + b"\0" + rf_raw + b"\0")
                parts.append(f"# Trusted skill file: response_first/{rubric_name}\n\n{rf_raw.decode('utf-8')}")
                base_id = skill_identity(self._root)
                identity = SkillIdentity.model_validate({
                    "id": base_id["id"],
                    "version": base_id["version"],
                    "sha256": digest.hexdigest(),
                })
            except (OSError, UnicodeError, IndexError, KeyError, TypeError, ValueError) as exc:
                if isinstance(exc, SkillBundleError):
                    raise
                raise SkillBundleError("Trusted response-first skill bundle could not be loaded.") from exc
            return SkillBundle(identity=identity, system_prompt="\n\n".join(parts))

        paths = (*SHARED, f"vulnerabilities/{RUBRICS[evaluation_type]}")
        parts = []
        root = self._root.resolve()
        try:
            for relative in paths:
                path = self._root / relative
                if not path.resolve().is_relative_to(root) or not path.is_file():
                    raise SkillBundleError(f"Required trusted skill file is unavailable: {relative}.")
                parts.append(f"# Trusted skill file: {relative}\n\n{path.read_text(encoding='utf-8')}")
            identity = SkillIdentity.model_validate(skill_identity(self._root))
        except (OSError, UnicodeError, IndexError, KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, SkillBundleError):
                raise
            raise SkillBundleError("Trusted skill bundle could not be loaded.") from exc
        return SkillBundle(identity=identity, system_prompt="\n\n".join(parts))
