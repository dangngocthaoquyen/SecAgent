"""G11.2 unit and contract tests for Context-Aware Generation Skills and Loader."""

from __future__ import annotations

import ast
import os
from pathlib import Path
import re
import shutil

from pydantic import ValidationError
import pytest

from generator import (
    ASI_CODE_TO_CATEGORY,
    ASI_PROFILE_FILES,
    DEFAULT_GENERATION_LIMITS,
    DEFAULT_GENERATOR_SKILLS_DIR,
    FORBIDDEN_LLM_OUTPUT_KEYS,
    GENERATOR_SKILL_ID,
    HARD_MAX_PER_ASI,
    HARD_MAX_TOTAL_CASES,
    KNOWN_APPLICATION_CONTEXT_FIELDS,
    MAX_CANDIDATE_PROMPT_UTF8_BYTES,
    GeneratedCandidateDraft,
    GenerationLimits,
    GeneratorSkillError,
    GeneratorSkillLoader,
    RawGenerationOutputContract,
    SHARED_SKILL_FILES,
    SUPPORTED_ASI_CODES,
)
from generator.constants import FORBIDDEN_EVALUATOR_SKILLS_DIR, REPO_ROOT
from generator.skills import _validate_relative_posix_path

EXPECTED_SKILL_VERSION = "1.0.1"


def _copy_skill_tree(dst: Path) -> Path:
    """Copy real generator_skills into an isolated temporary directory for mutation tests."""
    target = dst / "skills_copy"
    shutil.copytree(DEFAULT_GENERATOR_SKILLS_DIR, target)
    return target


def _valid_candidate(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "prompt": "Synthetic boundary test prompt for SYNTH-ITEM-01.",
        "description": "Checks a declared security boundary.",
        "strategy_tag": "boundary_check",
        "context_basis": ["purpose", "trust_boundaries"],
        "scope_note": "Descriptive metadata only: response-level boundary check using hypothetical placeholder.",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# 1. Loading all 4 supported OWASP ASI profiles & deterministic order/hashing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("asi_input", "expected_code", "expected_category"),
    [
        ("ASI01", "ASI01", "goal_hijacking"),
        ("ASI02", "ASI02", "tool_misuse"),
        ("ASI03", "ASI03", "identity_privilege_abuse"),
        ("ASI05", "ASI05", "unexpected_code_execution"),
        ("goal_hijacking", "ASI01", "goal_hijacking"),
        ("tool_misuse", "ASI02", "tool_misuse"),
        ("identity_privilege_abuse", "ASI03", "identity_privilege_abuse"),
        ("unexpected_code_execution", "ASI05", "unexpected_code_execution"),
    ],
)
def test_load_supported_asi_profiles_succeeds(
    asi_input: str, expected_code: str, expected_category: str
) -> None:
    loader = GeneratorSkillLoader()
    bundle = loader.load(asi_input)

    assert bundle.identity.id == GENERATOR_SKILL_ID
    assert bundle.identity.version == EXPECTED_SKILL_VERSION
    assert bundle.identity.schema_version == "1.0"
    assert bundle.identity.asi_code == expected_code
    assert bundle.identity.asi_category == expected_category
    assert re.fullmatch(r"[0-9a-f]{64}", bundle.identity.sha256)
    expected_files = (*SHARED_SKILL_FILES, ASI_PROFILE_FILES[expected_code])
    assert bundle.identity.files == expected_files
    assert bundle.total_bytes > 0
    assert bundle.system_prompt.strip()


def test_list_profiles_returns_all_four_asi_with_distinct_hashes() -> None:
    loader = GeneratorSkillLoader()
    profiles = loader.list_profiles()

    assert tuple(p.asi_code for p in profiles) == SUPPORTED_ASI_CODES
    assert len({p.sha256 for p in profiles}) == 4


def test_deterministic_concatenation_order() -> None:
    loader = GeneratorSkillLoader()
    bundle = loader.load("ASI02")

    markers = [
        f"# Trusted generator skill file: {rel}"
        for rel in (*SHARED_SKILL_FILES, ASI_PROFILE_FILES["ASI02"])
    ]
    positions = [bundle.system_prompt.index(marker) for marker in markers]
    assert positions == sorted(positions)


def test_hash_is_stable_across_repeats_and_worktree_paths(tmp_path: Path) -> None:
    copy_a = _copy_skill_tree(tmp_path / "worktree_alpha")
    copy_b = _copy_skill_tree(tmp_path / "nested" / "worktree_beta")

    # Convert line endings to CRLF in copy_b to verify OS-independent canonical hashing.
    for md_file in copy_b.rglob("*.md"):
        text = md_file.read_text(encoding="utf-8")
        md_file.write_bytes(text.replace("\n", "\r\n").encode("utf-8"))

    loader_real = GeneratorSkillLoader()
    loader_a = GeneratorSkillLoader(root=copy_a)
    loader_b = GeneratorSkillLoader(root=copy_b)

    for code in SUPPORTED_ASI_CODES:
        h_real_1 = loader_real.load(code).identity.sha256
        h_real_2 = loader_real.load(code).identity.sha256
        h_a = loader_a.load(code).identity.sha256
        h_b = loader_b.load(code).identity.sha256
        assert h_real_1 == h_real_2 == h_a == h_b


def test_hash_changes_when_loaded_skill_changes_and_stays_isolated(tmp_path: Path) -> None:
    skills_dir = _copy_skill_tree(tmp_path)
    loader = GeneratorSkillLoader(root=skills_dir)

    before_asi01 = loader.load("ASI01").identity.sha256
    before_asi02 = loader.load("ASI02").identity.sha256

    # Mutate only ASI01 profile -> ASI01 hash must change, ASI02 hash must remain unchanged.
    asi01_path = skills_dir / ASI_PROFILE_FILES["ASI01"]
    asi01_path.write_text(
        asi01_path.read_text(encoding="utf-8") + "\n<!-- synthetic note -->\n",
        encoding="utf-8",
    )
    assert loader.load("ASI01").identity.sha256 != before_asi01
    assert loader.load("ASI02").identity.sha256 == before_asi02

    # Mutate shared policy file -> both ASI01 and ASI02 hashes must change.
    after_asi01 = loader.load("ASI01").identity.sha256
    shared_path = skills_dir / "safety-and-scope-policy.md"
    shared_path.write_text(
        shared_path.read_text(encoding="utf-8") + "\n<!-- shared policy revision -->\n",
        encoding="utf-8",
    )
    assert loader.load("ASI01").identity.sha256 != after_asi01
    assert loader.load("ASI02").identity.sha256 != before_asi02


# ---------------------------------------------------------------------------
# 2. Fail-closed rejections: unsupported ASI, missing files, bad identity/version, size bounds
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_asi",
    [
        "",
        "   ",
        "ASI04",
        "ASI06",
        "ASI99",
        "prompt_injection",
        "sensitive_data_disclosure",
        "../evaluator_skills/security/SKILL.md",
        "profiles/asi01-goal-hijacking.md",
        "ASI01/../ASI02",
    ],
)
def test_reject_unsupported_asi(bad_asi: str) -> None:
    loader = GeneratorSkillLoader()
    with pytest.raises(GeneratorSkillError) as exc_info:
        loader.load(bad_asi)
    assert exc_info.value.code == "unsupported_asi"


@pytest.mark.parametrize("shared_file", SHARED_SKILL_FILES)
def test_missing_shared_skill_file_fails_closed(tmp_path: Path, shared_file: str) -> None:
    skills_dir = _copy_skill_tree(tmp_path)
    (skills_dir / shared_file).unlink()
    loader = GeneratorSkillLoader(root=skills_dir)

    with pytest.raises(GeneratorSkillError) as exc_info:
        loader.load("ASI01")
    assert exc_info.value.code == "skill_file_missing"


@pytest.mark.parametrize("asi_code", SUPPORTED_ASI_CODES)
def test_missing_profile_file_fails_closed(tmp_path: Path, asi_code: str) -> None:
    skills_dir = _copy_skill_tree(tmp_path)
    (skills_dir / ASI_PROFILE_FILES[asi_code]).unlink()
    loader = GeneratorSkillLoader(root=skills_dir)

    with pytest.raises(GeneratorSkillError) as exc_info:
        loader.load(asi_code)
    assert exc_info.value.code == "skill_file_missing"


def test_invalid_skill_identity_in_skill_md_rejected(tmp_path: Path) -> None:
    skills_dir = _copy_skill_tree(tmp_path)
    skill_md = skills_dir / "SKILL.md"
    skill_md.write_text(
        skill_md.read_text(encoding="utf-8").replace("name: secagent-g11-generator", "name: security"),
        encoding="utf-8",
    )
    loader = GeneratorSkillLoader(root=skills_dir)

    with pytest.raises(GeneratorSkillError) as exc_info:
        loader.load("ASI01")
    assert exc_info.value.code == "invalid_skill_identity"


def test_invalid_skill_version_in_skill_md_rejected(tmp_path: Path) -> None:
    skills_dir = _copy_skill_tree(tmp_path)
    skill_md = skills_dir / "SKILL.md"
    skill_md.write_text(
        skill_md.read_text(encoding="utf-8").replace(
            f'version: "{EXPECTED_SKILL_VERSION}"', 'version: "v1-beta"'
        ),
        encoding="utf-8",
    )
    loader = GeneratorSkillLoader(root=skills_dir)

    with pytest.raises(GeneratorSkillError) as exc_info:
        loader.load("ASI01")
    assert exc_info.value.code == "invalid_skill_version"


def test_profile_version_or_asi_mismatch_rejected(tmp_path: Path) -> None:
    skills_dir = _copy_skill_tree(tmp_path)
    prof = skills_dir / ASI_PROFILE_FILES["ASI03"]
    original = prof.read_text(encoding="utf-8")

    prof.write_text(
        original.replace(f'version: "{EXPECTED_SKILL_VERSION}"', 'version: "2.0.0"'),
        encoding="utf-8",
    )
    loader = GeneratorSkillLoader(root=skills_dir)
    with pytest.raises(GeneratorSkillError) as exc_info:
        loader.load("ASI03")
    assert exc_info.value.code == "invalid_skill_version"

    prof.write_text(original.replace("asi_code: ASI03", "asi_code: ASI01"), encoding="utf-8")
    with pytest.raises(GeneratorSkillError) as exc_info:
        loader.load("ASI03")
    assert exc_info.value.code == "invalid_skill_identity"


def test_file_and_bundle_size_bounds_enforced(tmp_path: Path) -> None:
    skills_dir = _copy_skill_tree(tmp_path)

    # Single file exceeds custom max_file_bytes
    tiny_file_loader = GeneratorSkillLoader(root=skills_dir, max_file_bytes=256, max_bundle_bytes=65536)
    with pytest.raises(GeneratorSkillError) as exc_info:
        tiny_file_loader.load("ASI01")
    assert exc_info.value.code == "skill_file_too_large"

    # Each file fits individually, but combined bundle exceeds max_bundle_bytes
    baseline = GeneratorSkillLoader(root=skills_dir).load("ASI01")
    max_single = max(
        (skills_dir / rel).stat().st_size for rel in baseline.identity.files
    )
    tight_bundle_loader = GeneratorSkillLoader(
        root=skills_dir,
        max_file_bytes=max_single + 1024,
        max_bundle_bytes=baseline.total_bytes - 10,
    )
    with pytest.raises(GeneratorSkillError) as exc_info:
        tight_bundle_loader.load("ASI01")
    assert exc_info.value.code == "skill_bundle_too_large"


# ---------------------------------------------------------------------------
# 3. Path traversal, symlink/out-of-directory rejection, and evaluator_skills isolation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "malicious_rel",
    [
        "../evaluator_skills/security/SKILL.md",
        "profiles/../../SKILL.md",
        "/etc/passwd",
        "C:/Windows/win.ini",
        "profiles\\asi01-goal-hijacking.md",
        "profiles/asi01\x00.md",
    ],
)
def test_relative_path_validator_rejects_traversal(malicious_rel: str) -> None:
    with pytest.raises(GeneratorSkillError) as exc_info:
        _validate_relative_posix_path(malicious_rel)
    assert exc_info.value.code in {"path_traversal_rejected", "invalid_skill_path"}


def test_out_of_directory_resolution_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    skills_dir = _copy_skill_tree(tmp_path)
    outside_file = tmp_path / "outside.md"
    outside_file.write_text("# outside\n", encoding="utf-8")

    # Simulate a path resolving outside the trusted skill root even if OS denies symlink creation.
    original_resolve = Path.resolve

    def fake_resolve(self: Path, strict: bool = False) -> Path:
        if self.name == "asi05-unexpected-code-execution.md":
            return original_resolve(outside_file, strict=True)
        return original_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", fake_resolve)
    loader = GeneratorSkillLoader(root=skills_dir)

    with pytest.raises(GeneratorSkillError) as exc_info:
        loader.load("ASI05")
    assert exc_info.value.code == "path_traversal_rejected"


def test_symlink_rejected_in_skill_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    skills_dir = _copy_skill_tree(tmp_path)
    outside_file = tmp_path / "external-skill.md"
    outside_file.write_text("# outside\n", encoding="utf-8")
    target_profile = skills_dir / ASI_PROFILE_FILES["ASI01"]

    # Attempt real OS symlink first; fall back to monkeypatching is_symlink on unprivileged Windows.
    symlink_created = False
    try:
        target_profile.unlink()
        os.symlink(outside_file, target_profile)
        symlink_created = True
    except OSError:
        target_profile.write_text("# restored\n", encoding="utf-8")
        orig_is_symlink = Path.is_symlink

        def fake_is_symlink(self: Path) -> bool:
            if self == target_profile:
                return True
            return orig_is_symlink(self)

        monkeypatch.setattr(Path, "is_symlink", fake_is_symlink)

    loader = GeneratorSkillLoader(root=skills_dir)
    with pytest.raises(GeneratorSkillError) as exc_info:
        loader.load("ASI01")
    assert exc_info.value.code == "skill_symlink_rejected"
    assert symlink_created or target_profile.exists()


def test_loader_never_reads_evaluator_skills(tmp_path: Path) -> None:
    # 1. Passing real evaluator_skills or its subdirectory must fail closed.
    for forbidden_root in (
        FORBIDDEN_EVALUATOR_SKILLS_DIR,
        FORBIDDEN_EVALUATOR_SKILLS_DIR / "security",
    ):
        loader = GeneratorSkillLoader(root=forbidden_root)
        with pytest.raises(GeneratorSkillError) as exc_info:
            loader.load("ASI01")
        assert exc_info.value.code == "evaluator_skills_forbidden"

    # 2. Even a synthetic temp directory named evaluator_skills must be rejected.
    fake_eval_dir = tmp_path / "evaluator_skills"
    shutil.copytree(DEFAULT_GENERATOR_SKILLS_DIR, fake_eval_dir)
    with pytest.raises(GeneratorSkillError) as exc_info:
        GeneratorSkillLoader(root=fake_eval_dir).load("ASI01")
    assert exc_info.value.code == "evaluator_skills_forbidden"

    # 3. Static AST import isolation check: generator backend has zero imports from Judge/G12 modules.
    forbidden_roots = {"evaluators", "integrations", "observers", "targets", "testing"}
    gen_src_dir = REPO_ROOT / "backend" / "src" / "generator"
    for py_file in gen_src_dir.rglob("*.py"):
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top_pkg = alias.name.split(".", 1)[0]
                    assert top_pkg not in forbidden_roots, f"Forbidden import {alias.name!r} in {py_file.name}"
            elif isinstance(node, ast.ImportFrom) and node.module:
                top_pkg = node.module.split(".", 1)[0]
                assert top_pkg not in forbidden_roots, f"Forbidden import from {node.module!r} in {py_file.name}"


# ---------------------------------------------------------------------------
# 4. Structured Output Contract & R03 Corrections (R03A - R03E)
# ---------------------------------------------------------------------------


def test_structured_output_contract_accepts_valid_draft_without_verdict_or_rules() -> None:
    valid_payload = {
        "schema_version": "1.0",
        "asi_category": "ASI02",
        "context_gaps": ["available_tools not confirmed"],
        "candidates": [
            _valid_candidate(
                prompt="Please perform a restricted action on SYNTH-ITEM-01 without confirmation.",
                description="Tests whether the agent enforces the declared confirmation gate.",
                strategy_tag="confirmation_gate_bypass",
                context_basis=["purpose", "authorization_required", "prohibited_resources"],
                scope_note="Descriptive only: tool_intent_response check using hypothetical placeholder.",
            )
        ],
    }
    parsed = RawGenerationOutputContract.model_validate(valid_payload)
    assert parsed.asi_category == "ASI02"
    assert len(parsed.candidates) == 1
    assert parsed.candidates[0].strategy_tag == "confirmation_gate_bypass"


@pytest.mark.parametrize("forbidden_key", sorted(FORBIDDEN_LLM_OUTPUT_KEYS))
def test_structured_output_contract_rejects_authority_escalating_fields(forbidden_key: str) -> None:
    base_candidate = _valid_candidate()
    # Forbidden key inside candidate object must be rejected by extra="forbid".
    with pytest.raises(ValidationError):
        GeneratedCandidateDraft.model_validate({**base_candidate, forbidden_key: "unauthorized"})

    # Forbidden key at top-level output object must also be rejected.
    with pytest.raises(ValidationError):
        RawGenerationOutputContract.model_validate(
            {
                "schema_version": "1.0",
                "asi_category": "ASI01",
                "candidates": [base_candidate],
                forbidden_key: "unauthorized",
            }
        )


def test_r03a_prompt_utf8_byte_bounds_with_multibyte_characters() -> None:
    # Exact 4096 ASCII bytes -> accepted
    ascii_exact = "a" * MAX_CANDIDATE_PROMPT_UTF8_BYTES
    assert len(ascii_exact.encode("utf-8")) == 4096
    parsed_ascii = GeneratedCandidateDraft.model_validate(_valid_candidate(prompt=ascii_exact))
    assert len(parsed_ascii.prompt.encode("utf-8")) == 4096

    # Exact 4096 UTF-8 bytes using 2-byte Vietnamese char 'ă' (2048 chars = 4096 bytes) -> accepted
    vi_exact = "ă" * (MAX_CANDIDATE_PROMPT_UTF8_BYTES // 2)
    assert len(vi_exact) == 2048
    assert len(vi_exact.encode("utf-8")) == 4096
    parsed_vi = GeneratedCandidateDraft.model_validate(_valid_candidate(prompt=vi_exact))
    assert len(parsed_vi.prompt.encode("utf-8")) == 4096

    # 2049 chars of 'ă' = 4098 UTF-8 bytes (char count < 4096, bytes > 4096) -> REJECTED
    vi_over = "ă" * (MAX_CANDIDATE_PROMPT_UTF8_BYTES // 2 + 1)
    assert len(vi_over) < MAX_CANDIDATE_PROMPT_UTF8_BYTES
    assert len(vi_over.encode("utf-8")) == 4098
    with pytest.raises(ValidationError, match="4096 UTF-8 bytes"):
        GeneratedCandidateDraft.model_validate(_valid_candidate(prompt=vi_over))

    # 1025 4-byte emoji chars = 4100 UTF-8 bytes -> REJECTED
    emoji_over = "😀" * (MAX_CANDIDATE_PROMPT_UTF8_BYTES // 4 + 1)
    assert len(emoji_over) == 1025
    assert len(emoji_over.encode("utf-8")) == 4100
    with pytest.raises(ValidationError, match="4096 UTF-8 bytes"):
        GeneratedCandidateDraft.model_validate(_valid_candidate(prompt=emoji_over))


def test_r03b_context_basis_allowlist_and_optional_fields() -> None:
    # All canonical fields + optional agent_identity & reviewed_policy are accepted and deduplicated.
    draft = GeneratedCandidateDraft.model_validate(
        _valid_candidate(
            context_basis=["purpose", "agent_identity", "reviewed_policy", "purpose", "users"]
        )
    )
    assert draft.context_basis == ("purpose", "agent_identity", "reviewed_policy", "users")
    assert {"agent_identity", "reviewed_policy"}.issubset(KNOWN_APPLICATION_CONTEXT_FIELDS)

    # Invented or unknown fields must be rejected even if they match snake_case regex.
    for invented in ("invented_field", "secret_admin_tool", "system_prompt", "expected_verdict"):
        with pytest.raises(ValidationError, match="KNOWN_APPLICATION_CONTEXT_FIELDS"):
            GeneratedCandidateDraft.model_validate(_valid_candidate(context_basis=["purpose", invented]))


def test_r03c_scope_note_is_required_and_nonblank() -> None:
    missing_scope_note = _valid_candidate()
    missing_scope_note.pop("scope_note")
    with pytest.raises(ValidationError):
        GeneratedCandidateDraft.model_validate(missing_scope_note)

    for invalid_scope in (None, "", "   "):
        with pytest.raises(ValidationError):
            GeneratedCandidateDraft.model_validate(_valid_candidate(scope_note=invalid_scope))


def test_r03d_generation_limits_hard_ceilings_and_per_asi_counts() -> None:
    assert DEFAULT_GENERATION_LIMITS.min_per_asi == 1
    assert DEFAULT_GENERATION_LIMITS.default_per_asi == 5
    assert DEFAULT_GENERATION_LIMITS.max_per_asi == HARD_MAX_PER_ASI == 50
    assert DEFAULT_GENERATION_LIMITS.max_total_cases == HARD_MAX_TOTAL_CASES == 50

    # Hard ceilings cannot be overridden above 50 total or 50 per ASI.
    with pytest.raises(ValidationError):
        GenerationLimits(max_total_cases=100)
    with pytest.raises(ValidationError):
        GenerationLimits(max_total_cases=51)
    with pytest.raises(ValidationError):
        GenerationLimits(max_per_asi=51)
    with pytest.raises(ValidationError):
        GenerationLimits(max_per_asi=60)

    # Single-ASI full allocation (50) and multi-ASI distinct counts summing <= 50 are allowed.
    assert DEFAULT_GENERATION_LIMITS.validate_per_asi_counts({"ASI03": 50}) == {"ASI03": 50}
    validated = DEFAULT_GENERATION_LIMITS.validate_per_asi_counts(
        {"ASI01": 10, "ASI03": 20, "ASI05": 20}
    )
    assert validated == {"ASI01": 10, "ASI03": 20, "ASI05": 20}

    # Duplicate ASI aliases rejected (ASI01 + goal_hijacking).
    with pytest.raises(ValueError, match="Duplicate ASI category"):
        DEFAULT_GENERATION_LIMITS.validate_per_asi_counts({"ASI01": 2, "goal_hijacking": 3})

    # Non-integer / boolean / invalid counts rejected.
    for bad_count in (True, False, 3.5, "5", 0, -1, 51):
        with pytest.raises(ValueError):
            DEFAULT_GENERATION_LIMITS.validate_per_asi_counts({"ASI01": bad_count})  # type: ignore[dict-item]

    # Exceeding total max (30 + 30 = 60 > 50 and 15 * 4 = 60 > 50) rejected.
    with pytest.raises(ValueError, match="exceeds maximum limit of 50"):
        DEFAULT_GENERATION_LIMITS.validate_per_asi_counts({"ASI03": 30, "ASI05": 30})
    with pytest.raises(ValueError, match="exceeds maximum limit of 50"):
        DEFAULT_GENERATION_LIMITS.validate_per_asi_counts(
            {"ASI01": 15, "ASI02": 15, "ASI03": 15, "ASI05": 15}
        )

    # Tighter custom limits within locked hard ceilings remain valid.
    custom = GenerationLimits(min_per_asi=1, default_per_asi=3, max_per_asi=10, max_total_cases=25)
    assert custom.validate_per_asi_counts({"goal_hijacking": 10, "tool_misuse": 5}) == {
        "ASI01": 10,
        "ASI02": 5,
    }


def test_r03e_empty_candidates_allowed_only_with_context_gaps() -> None:
    # Empty candidates with non-empty context_gaps -> accepted as diagnostic contract output
    empty_valid = RawGenerationOutputContract.model_validate(
        {
            "schema_version": "1.0",
            "asi_category": "ASI03",
            "context_gaps": [
                "Only generic trust_boundaries provided; identity/role/privilege boundaries unestablished."
            ],
            "candidates": [],
        }
    )
    assert empty_valid.candidates == ()
    assert len(empty_valid.context_gaps) == 1

    # Empty candidates WITHOUT context_gaps -> REJECTED
    with pytest.raises(ValidationError, match="context_gaps"):
        RawGenerationOutputContract.model_validate(
            {
                "schema_version": "1.0",
                "asi_category": "ASI03",
                "context_gaps": [],
                "candidates": [],
            }
        )

    # Exceeding HARD_MAX_PER_ASI (16 candidates) -> REJECTED
    with pytest.raises(ValidationError):
        RawGenerationOutputContract.model_validate(
            {
                "schema_version": "1.0",
                "asi_category": "ASI01",
                "candidates": [_valid_candidate(prompt=f"Prompt {i}") for i in range(HARD_MAX_PER_ASI + 1)],
            }
        )


# ---------------------------------------------------------------------------
# 5. Skill Content Contract Tests (R01 OWASP Semantics, R02 Shared Policies, No Hardcoding)
# ---------------------------------------------------------------------------


def test_loaded_bundles_contain_r02_shared_policies_and_untrusted_context() -> None:
    loader = GeneratorSkillLoader()
    for code in SUPPORTED_ASI_CODES:
        prompt = loader.load(code).system_prompt.lower()
        assert "untrusted data" in prompt
        assert "prompt injection" in prompt
        assert "authorized local" in prompt
        assert "synthetic" in prompt
        assert "hypothetical placeholder" in prompt
        assert "disputed boundary" in prompt
        assert "descriptive metadata only" in prompt
        assert "semantic applicability" in prompt
        assert '"candidates": []' in prompt
        assert "expected_verdict" in prompt


def test_r01_owasp_asi_semantic_alignment_in_profiles() -> None:
    loader = GeneratorSkillLoader()

    asi01 = loader.load("ASI01").system_prompt.lower()
    assert "legitimate task change" in asi01
    assert "not every response outside `purpose` is goal hijack" in asi01

    asi02 = loader.load("ASI02").system_prompt.lower()
    assert "within its currently available or delegated permissions" in asi02
    assert "distinction from asi03" in asi02
    assert "distinction from asi05" in asi02
    assert "lack of an independent runtime observer does **not** automatically prove" in asi02

    asi03 = loader.load("ASI03").system_prompt.lower()
    assert "agent identity" in asi03
    assert "delegated privileges" in asi03
    assert "user permissions vs agent permissions" in asi03
    assert "generic `trust_boundaries` sentence alone" in asi03

    asi05 = loader.load("ASI05").system_prompt.lower()
    assert "code/command artifact in response" in asi05
    assert "target-reported execution action" in asi05
    assert "independently verified execution" in asi05
    assert "generating code text does not automatically prove" in asi05
    assert "legitimate coding assistance is not unexpected code execution" in asi05
    assert "mere presence of arbitrary `available_tools`" in asi05
    assert "do not let the llm unilaterally switch to response-only" in asi05


def test_skill_files_contain_no_hardcoded_lab_or_bot_identifiers() -> None:
    forbidden_terms = (
        "staff100",
        "ord-1003",
        "dvaa",
        "aigoat",
        "researchbot",
        "toolbot",
        "codebot",
        "flightbot",
        "securebot",
    )
    for md_file in DEFAULT_GENERATOR_SKILLS_DIR.rglob("*.md"):
        lowered = md_file.read_text(encoding="utf-8").lower()
        for term in forbidden_terms:
            assert term not in lowered, f"Forbidden hardcoded term {term!r} found in {md_file.name}"


@pytest.mark.parametrize("asi_code", SUPPORTED_ASI_CODES)
def test_each_profile_contains_all_ten_required_sections(asi_code: str) -> None:
    profile_path = DEFAULT_GENERATOR_SKILLS_DIR / ASI_PROFILE_FILES[asi_code]
    text = profile_path.read_text(encoding="utf-8")
    for section_num in range(1, 11):
        assert f"\n## {section_num}. " in text, (
            f"Profile {profile_path.name} missing required section ## {section_num}."
        )
    assert ASI_CODE_TO_CATEGORY[asi_code] in text
