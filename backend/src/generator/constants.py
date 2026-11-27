"""Centralized constants and configuration defaults for SecAgent G11 Generator."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

AsiCode = Literal["ASI01", "ASI02", "ASI03", "ASI05"]
AsiCategory = Literal[
    "goal_hijacking",
    "tool_misuse",
    "identity_privilege_abuse",
    "unexpected_code_execution",
]

GENERATOR_SKILL_ID: Literal["secagent-g11-generator"] = "secagent-g11-generator"
GENERATOR_SKILL_SCHEMA_VERSION: Literal["1.0"] = "1.0"
GENERATOR_SOURCE_TOOL: Literal["secagent_g11_generator"] = "secagent_g11_generator"

SUPPORTED_ASI_CODES: tuple[AsiCode, ...] = ("ASI01", "ASI02", "ASI03", "ASI05")

ASI_CODE_TO_CATEGORY: dict[AsiCode, AsiCategory] = {
    "ASI01": "goal_hijacking",
    "ASI02": "tool_misuse",
    "ASI03": "identity_privilege_abuse",
    "ASI05": "unexpected_code_execution",
}

CATEGORY_TO_ASI_CODE: dict[AsiCategory, AsiCode] = {
    category: code for code, category in ASI_CODE_TO_CATEGORY.items()
}

# Exact allowlist of trusted Generation Skill files and deterministic load order.
SHARED_SKILL_FILES: tuple[str, ...] = (
    "SKILL.md",
    "safety-and-scope-policy.md",
    "untrusted-context-policy.md",
)

ASI_PROFILE_FILES: dict[AsiCode, str] = {
    "ASI01": "profiles/asi01-goal-hijacking.md",
    "ASI02": "profiles/asi02-tool-misuse.md",
    "ASI03": "profiles/asi03-identity-privilege-abuse.md",
    "ASI05": "profiles/asi05-unexpected-code-execution.md",
}

# Skill file and bundle byte bounds (fail-closed in GeneratorSkillLoader).
DEFAULT_MAX_SKILL_FILE_BYTES: int = 32 * 1024  # 32 KiB per Markdown file
DEFAULT_MAX_SKILL_BUNDLE_BYTES: int = 96 * 1024  # 96 KiB per loaded ASI bundle

# Centralized testcase generation limits (aligned with GenericRunService _MAX_WEB_CASES=50).
# Hard ceilings lock v1 bounds; DatasetNormalizer (100) and GenericRunService (50) remain untouched.
DEFAULT_MIN_PER_ASI: int = 1
DEFAULT_PER_ASI: int = 5
DEFAULT_MAX_PER_ASI: int = 50
DEFAULT_MAX_TOTAL_CASES: int = 50
HARD_MAX_PER_ASI: int = 50
HARD_MAX_TOTAL_CASES: int = 50

# Candidate prompt byte bound per G11.1 design (enforced in UTF-8 bytes, not char count alone).
MAX_CANDIDATE_PROMPT_UTF8_BYTES: int = 4096

# Canonical ApplicationContextDraft text fields allowed in candidate context_basis.
KNOWN_APPLICATION_CONTEXT_FIELDS: frozenset[str] = frozenset({
    "purpose",
    "features",
    "domain_industry",
    "operational_constraints",
    "available_tools",
    "users",
    "allowed_resources",
    "prohibited_resources",
    "authorized_actions",
    "authorization_required",
    "trust_boundaries",
    "sensitive_data_categories",
    "protected_assets",
    "high_risk_actions",
    "data_handling_restrictions",
    "required_instructions",
    "business_restrictions",
    "redteam_personas",
    # Optional future/policy enrichment fields (read-only when present).
    "agent_identity",
    "reviewed_policy",
})

# Keys that LLM generation outputs must NEVER be allowed to emit.
FORBIDDEN_LLM_OUTPUT_KEYS: frozenset[str] = frozenset({
    "id",
    "testcase_id",
    "internal_id",
    "verdict",
    "expected_verdict",
    "classification",
    "assertions",
    "assert",
    "rules",
    "evaluation_rules",
    "markers",
    "trusted_context",
    "evidence",
    "execution_verified",
    "execution_authorized",
    "policy_override",
})

REPO_ROOT: Path = Path(__file__).resolve().parents[3]
DEFAULT_GENERATOR_SKILLS_DIR: Path = REPO_ROOT / "generator_skills"
FORBIDDEN_EVALUATOR_SKILLS_DIR: Path = REPO_ROOT / "evaluator_skills"
