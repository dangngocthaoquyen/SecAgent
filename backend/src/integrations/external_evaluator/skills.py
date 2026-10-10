"""Load only the trusted Markdown files selected by an allowlisted type."""

from dataclasses import dataclass
from pathlib import Path

from integrations.external_evaluator.identity import SKILLS, skill_identity
from integrations.external_evaluator.models import EvaluationType, SkillIdentity


RUBRICS = {
    "goal_hijacking": "goal-hijacking.md",
    "prompt_injection": "prompt-injection.md",
    "tool_misuse": "tool-misuse.md",
    "sensitive_data_disclosure": "sensitive-data-disclosure.md",
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

    def load(self, evaluation_type: EvaluationType) -> SkillBundle:
        if evaluation_type not in RUBRICS:
            raise SkillBundleError("Unsupported evaluation type.")
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
