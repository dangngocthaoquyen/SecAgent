"""Fail-closed allowlisted loader for SecAgent G11 Generation Skills.

Independent of Judge SkillBundleLoader (`integrations.external_evaluator`) and
never reads `evaluator_skills/`. Computes deterministic, path-independent
SHA-256 digests over canonical UTF-8 skill contents in a fixed load order.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any

import yaml

from generator.constants import (
    ASI_CODE_TO_CATEGORY,
    ASI_PROFILE_FILES,
    AsiCode,
    DEFAULT_GENERATOR_SKILLS_DIR,
    DEFAULT_MAX_SKILL_BUNDLE_BYTES,
    DEFAULT_MAX_SKILL_FILE_BYTES,
    FORBIDDEN_EVALUATOR_SKILLS_DIR,
    GENERATOR_SKILL_ID,
    GENERATOR_SKILL_SCHEMA_VERSION,
    SHARED_SKILL_FILES,
    SUPPORTED_ASI_CODES,
)
from generator.models import GeneratorSkillBundle, GeneratorSkillIdentity, normalize_asi_code

_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


class GeneratorSkillError(ValueError):
    """Fail-closed diagnostic error raised when trusted generation skills cannot be loaded."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _is_symlink_or_reparse(path: Path) -> bool:
    """Return True if path is a symlink or Windows reparse point/junction."""
    try:
        if path.is_symlink():
            return True
        if os.name == "nt" and path.exists():
            attrs = getattr(path.lstat(), "st_file_attributes", 0)
            if attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                return True
    except OSError:
        return True
    return False


def _validate_relative_posix_path(relative: str) -> tuple[str, ...]:
    """Validate that a relative skill path contains no traversal or absolute components."""
    if not isinstance(relative, str) or not relative or "\x00" in relative or "\\" in relative:
        raise GeneratorSkillError("invalid_skill_path", f"Invalid skill relative path: {relative!r}.")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ":" in relative:
        raise GeneratorSkillError("path_traversal_rejected", f"Absolute skill path rejected: {relative!r}.")
    parts = pure.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise GeneratorSkillError("path_traversal_rejected", f"Path traversal rejected: {relative!r}.")
    return parts


def _parse_frontmatter(text: str, *, label: str) -> dict[str, Any]:
    """Parse strict YAML frontmatter bounded by leading '---' markers."""
    if not text.startswith("---\n"):
        raise GeneratorSkillError("invalid_skill_frontmatter", f"Missing YAML frontmatter in {label}.")
    parts = text.split("\n---\n", 1)
    if len(parts) != 2:
        raise GeneratorSkillError("invalid_skill_frontmatter", f"Unterminated YAML frontmatter in {label}.")
    raw_yaml = parts[0][4:]
    try:
        loaded = yaml.safe_load(raw_yaml)
    except yaml.YAMLError as exc:
        raise GeneratorSkillError("invalid_skill_frontmatter", f"Malformed YAML frontmatter in {label}.") from exc
    if not isinstance(loaded, dict):
        raise GeneratorSkillError("invalid_skill_frontmatter", f"YAML frontmatter in {label} must be a mapping.")
    return loaded


class GeneratorSkillLoader:
    """Allowlisted, fail-closed loader for G11 Generation Skill bundles."""

    def __init__(
        self,
        root: Path = DEFAULT_GENERATOR_SKILLS_DIR,
        *,
        max_file_bytes: int = DEFAULT_MAX_SKILL_FILE_BYTES,
        max_bundle_bytes: int = DEFAULT_MAX_SKILL_BUNDLE_BYTES,
    ) -> None:
        if isinstance(max_file_bytes, bool) or not isinstance(max_file_bytes, int) or max_file_bytes <= 0:
            raise ValueError("max_file_bytes must be a positive integer.")
        if isinstance(max_bundle_bytes, bool) or not isinstance(max_bundle_bytes, int) or max_bundle_bytes <= 0:
            raise ValueError("max_bundle_bytes must be a positive integer.")
        self._root = Path(root)
        self._max_file_bytes = max_file_bytes
        self._max_bundle_bytes = max_bundle_bytes

    def _validate_root(self) -> Path:
        root_raw = self._root
        if not root_raw.exists():
            raise GeneratorSkillError("skill_root_missing", "Generation skill directory does not exist.")
        if _is_symlink_or_reparse(root_raw):
            raise GeneratorSkillError("skill_symlink_rejected", "Linked generation skill directory is unsupported.")
        if not root_raw.is_dir():
            raise GeneratorSkillError("skill_root_invalid", "Generation skill root must be a directory.")

        resolved_root = root_raw.resolve(strict=True)
        # Never allow reading from Judge's evaluator_skills directory.
        try:
            forbidden_resolved = FORBIDDEN_EVALUATOR_SKILLS_DIR.resolve(strict=False)
            if resolved_root == forbidden_resolved or resolved_root.is_relative_to(forbidden_resolved):
                raise GeneratorSkillError(
                    "evaluator_skills_forbidden",
                    "GeneratorSkillLoader must never read from evaluator_skills.",
                )
        except OSError as exc:
            raise GeneratorSkillError("skill_root_invalid", "Could not verify skill root boundary.") from exc

        if any(part.lower() == "evaluator_skills" for part in resolved_root.parts):
            raise GeneratorSkillError(
                "evaluator_skills_forbidden",
                "GeneratorSkillLoader refuses directories named evaluator_skills.",
            )
        return resolved_root

    def _read_contained_file(self, resolved_root: Path, relative: str) -> tuple[str, bytes]:
        parts = _validate_relative_posix_path(relative)

        # Check every intermediate component and the final file for symlinks/reparse points.
        current = resolved_root
        for part in parts:
            current = current / part
            if _is_symlink_or_reparse(current):
                raise GeneratorSkillError(
                    "skill_symlink_rejected",
                    f"Symlink or reparse point rejected in skill path: {relative}.",
                )

        if not current.exists() or not current.is_file():
            raise GeneratorSkillError("skill_file_missing", f"Required generation skill file is missing: {relative}.")

        try:
            resolved_file = current.resolve(strict=True)
        except OSError as exc:
            raise GeneratorSkillError("skill_file_unreadable", f"Could not resolve skill file: {relative}.") from exc

        if not resolved_file.is_relative_to(resolved_root):
            raise GeneratorSkillError(
                "path_traversal_rejected",
                f"Skill file resolves outside the trusted skill directory: {relative}.",
            )
        if any(part.lower() == "evaluator_skills" for part in resolved_file.parts):
            raise GeneratorSkillError(
                "evaluator_skills_forbidden",
                f"Skill file resolves inside forbidden evaluator_skills: {relative}.",
            )

        try:
            if resolved_file.stat().st_size > self._max_file_bytes:
                raise GeneratorSkillError(
                    "skill_file_too_large",
                    f"Skill file {relative} exceeds maximum allowed size of {self._max_file_bytes} bytes.",
                )
            with resolved_file.open("rb") as stream:
                raw_bytes = stream.read(self._max_file_bytes + 1)
        except GeneratorSkillError:
            raise
        except OSError as exc:
            raise GeneratorSkillError("skill_file_unreadable", f"Could not read skill file: {relative}.") from exc

        if len(raw_bytes) > self._max_file_bytes:
            raise GeneratorSkillError(
                "skill_file_too_large",
                f"Skill file {relative} exceeds maximum allowed size of {self._max_file_bytes} bytes.",
            )
        if not raw_bytes:
            raise GeneratorSkillError("skill_file_empty", f"Skill file {relative} must not be empty.")

        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise GeneratorSkillError("skill_invalid_encoding", f"Skill file {relative} is not valid UTF-8.") from exc

        canonical_text = text.replace("\r\n", "\n").replace("\r", "\n")
        canonical_bytes = canonical_text.encode("utf-8")
        if len(canonical_bytes) > self._max_file_bytes:
            raise GeneratorSkillError(
                "skill_file_too_large",
                f"Skill file {relative} exceeds maximum allowed size of {self._max_file_bytes} bytes.",
            )
        return canonical_text, canonical_bytes

    def load(self, asi_identifier: str) -> GeneratorSkillBundle:
        """Load and verify the allowlisted Generation Skill bundle for one OWASP ASI."""
        try:
            asi_code: AsiCode = normalize_asi_code(asi_identifier)
        except ValueError as exc:
            raise GeneratorSkillError("unsupported_asi", str(exc)) from exc

        resolved_root = self._validate_root()
        profile_rel = ASI_PROFILE_FILES[asi_code]
        ordered_files: tuple[str, ...] = (*SHARED_SKILL_FILES, profile_rel)

        digest = hashlib.sha256()
        sections: list[str] = []
        total_bytes = 0
        skill_version: str | None = None
        expected_category = ASI_CODE_TO_CATEGORY[asi_code]

        for relative in ordered_files:
            canonical_text, canonical_bytes = self._read_contained_file(resolved_root, relative)
            total_bytes += len(canonical_bytes)
            if total_bytes > self._max_bundle_bytes:
                raise GeneratorSkillError(
                    "skill_bundle_too_large",
                    f"Generation skill bundle for {asi_code} exceeds {self._max_bundle_bytes} bytes.",
                )

            if relative == "SKILL.md":
                meta = _parse_frontmatter(canonical_text, label=relative)
                if meta.get("name") != GENERATOR_SKILL_ID:
                    raise GeneratorSkillError(
                        "invalid_skill_identity",
                        f"SKILL.md name must be {GENERATOR_SKILL_ID!r}.",
                    )
                metadata_block = meta.get("metadata")
                if not isinstance(metadata_block, dict):
                    raise GeneratorSkillError("invalid_skill_version", "SKILL.md metadata block is missing.")
                raw_version = metadata_block.get("version")
                if not isinstance(raw_version, str) or not _SEMVER_RE.fullmatch(raw_version.strip()):
                    raise GeneratorSkillError(
                        "invalid_skill_version",
                        "SKILL.md metadata.version must be a valid X.Y.Z semantic version.",
                    )
                if metadata_block.get("schema_version") != GENERATOR_SKILL_SCHEMA_VERSION:
                    raise GeneratorSkillError(
                        "invalid_skill_schema_version",
                        f"SKILL.md metadata.schema_version must be {GENERATOR_SKILL_SCHEMA_VERSION!r}.",
                    )
                skill_version = raw_version.strip()
            elif relative == profile_rel:
                prof_meta = _parse_frontmatter(canonical_text, label=relative)
                if prof_meta.get("skill_id") != GENERATOR_SKILL_ID:
                    raise GeneratorSkillError(
                        "invalid_skill_identity",
                        f"Profile {relative} skill_id must be {GENERATOR_SKILL_ID!r}.",
                    )
                if prof_meta.get("asi_code") != asi_code:
                    raise GeneratorSkillError(
                        "invalid_skill_identity",
                        f"Profile {relative} asi_code must match {asi_code!r}.",
                    )
                if prof_meta.get("asi_category") != expected_category:
                    raise GeneratorSkillError(
                        "invalid_skill_identity",
                        f"Profile {relative} asi_category must match {expected_category!r}.",
                    )
                prof_version = prof_meta.get("version")
                if not isinstance(prof_version, str) or prof_version.strip() != skill_version:
                    raise GeneratorSkillError(
                        "invalid_skill_version",
                        f"Profile {relative} version must match SKILL.md version ({skill_version!r}).",
                    )

            # Path-independent deterministic hash: relative POSIX path + canonical content bytes.
            digest.update(relative.encode("utf-8") + b"\0" + canonical_bytes + b"\0")
            sections.append(f"# Trusted generator skill file: {relative}\n\n{canonical_text}")

        assert skill_version is not None
        identity = GeneratorSkillIdentity(
            id=GENERATOR_SKILL_ID,
            version=skill_version,
            schema_version=GENERATOR_SKILL_SCHEMA_VERSION,
            asi_code=asi_code,
            asi_category=expected_category,
            sha256=digest.hexdigest(),
            files=ordered_files,
        )
        return GeneratorSkillBundle(
            identity=identity,
            system_prompt="\n\n".join(sections),
            total_bytes=total_bytes,
        )

    def list_profiles(self) -> tuple[GeneratorSkillIdentity, ...]:
        """Load and return verified identities for all four supported OWASP ASI profiles."""
        return tuple(self.load(code).identity for code in SUPPORTED_ASI_CODES)
