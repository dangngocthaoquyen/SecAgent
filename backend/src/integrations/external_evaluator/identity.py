"""Canonical identities shared with the Week 5 GH dataset exporter."""

import hashlib
import json
from pathlib import Path

import yaml


SKILLS = Path(__file__).resolve().parents[4] / "evaluator_skills" / "security"


def canonical_hash(value: object) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def skill_identity(directory: Path = SKILLS) -> dict[str, str]:
    frontmatter = (directory / "SKILL.md").read_text(encoding="utf-8").split("---", 2)[1]
    version = str(yaml.safe_load(frontmatter)["metadata"]["version"])
    digest = hashlib.sha256()
    for path in sorted(directory.rglob("*.md"), key=lambda p: p.relative_to(directory).as_posix()):
        digest.update(path.relative_to(directory).as_posix().encode("utf-8") + b"\0")
        digest.update(path.read_bytes() + b"\0")
    return {"id": "security", "version": version, "sha256": digest.hexdigest()}
