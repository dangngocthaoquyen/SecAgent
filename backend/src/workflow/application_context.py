"""Operator-declared target descriptions. Never an evaluation policy or evidence source."""
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import secrets
from typing import Literal

from pydantic import Field, model_validator

from workflow.models import ClosedModel, Identifier

FieldProvenance = Literal["discovered_observed", "suggested_unverified", "operator_confirmed"]


class ApplicationContextDraft(ClosedModel):
    target_id: Identifier
    target_revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    # A. Core Application Details
    purpose: str = Field(default="", max_length=1000)
    features: str = Field(default="", max_length=1000)
    domain_industry: str = Field(default="", max_length=1000)
    operational_constraints: str = Field(default="", max_length=1000)
    # B. Access & Permissions
    available_tools: str = Field(default="", max_length=1000)
    users: str = Field(default="", max_length=1000)
    allowed_resources: str = Field(default="", max_length=1000)
    prohibited_resources: str = Field(default="", max_length=1000)
    authorized_actions: str = Field(default="", max_length=1000)
    authorization_required: str = Field(default="", max_length=1000)
    trust_boundaries: str = Field(default="", max_length=1000)
    # C. Data & Content
    sensitive_data_categories: str = Field(default="", max_length=1000)
    protected_assets: str = Field(default="", max_length=1000)
    high_risk_actions: str = Field(default="", max_length=1000)
    data_handling_restrictions: str = Field(default="", max_length=1000)
    # D. Business Context
    required_instructions: str = Field(default="", max_length=1000)
    business_restrictions: str = Field(default="", max_length=1000)
    # E. Red Team User
    redteam_personas: str = Field(default="", max_length=1000)
    # Provenance per field (discovered_observed / suggested_unverified / operator_confirmed)
    field_provenance: dict[str, FieldProvenance] = Field(default_factory=dict)

    @model_validator(mode="after")
    def reject_obvious_credentials(self):
        for key, value in self.model_dump().items():
            if key in {"target_id", "target_revision", "field_provenance"} or not isinstance(value, str):
                continue
            if re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:api[_-]?key|password|secret|token)\s*[:=]\s*\S+", value, re.I):
                raise ValueError("Application Context must not contain credential values.")
        return self


class SaveApplicationContext(ClosedModel):
    draft: ApplicationContextDraft
    expected_revision: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    safe_description_confirmed: bool


class ApplicationContextStore:
    """Separate, revision-bound operator metadata with no Judge or Runner path."""

    def __init__(self, catalog):
        self.catalog = catalog
        self.root = catalog.data_dir / "application-contexts"
        if self.root.is_symlink():
            raise ValueError("Linked application context directory is unsupported.")
        self.root.mkdir(mode=0o700, exist_ok=True)

    def _path(self, target_id: Identifier) -> Path:
        return self.root / f"{target_id}.json"

    def read(self, target_id: Identifier):
        if target_id not in self.catalog._targets:
            raise ValueError("Unknown target.")
        if self.root.is_symlink():
            raise ValueError("Linked application context directory is unsupported.")
        path = self._path(target_id)
        if path.is_symlink():
            raise ValueError("Linked application context is unsupported.")
        if not path.exists():
            return None
        if not path.is_file() or path.stat().st_size > 16384:
            raise ValueError("Invalid application context file.")
        row = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(row, dict):
            raise ValueError("Invalid application context document.")
        if row.get("schema_version") != "1.0.0" or row.get("provenance") != "operator_declared":
            raise ValueError("Invalid application context provenance.")
        draft = ApplicationContextDraft.model_validate(row.get("draft"))
        if draft.target_id != target_id:
            raise ValueError("Application context target mismatch.")
        expected = sha256(json.dumps(draft.model_dump(), sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        if row.get("revision_sha256") != expected:
            raise ValueError("Application context integrity failure.")
        return row

    def save(self, item: SaveApplicationContext):
        draft = item.draft
        if item.safe_description_confirmed is not True:
            raise ValueError("Confirm that the description contains no real secrets.")
        if self.catalog._revisions.get(draft.target_id) != draft.target_revision:
            raise ValueError("Target revision changed.")
        prior = self.read(draft.target_id)
        if item.expected_revision != (prior["revision_sha256"] if prior else None):
            raise ValueError("Application context revision changed.")
        raw_draft = draft.model_dump()
        row = {"schema_version": "1.0.0", "provenance": "operator_declared",
               "revision_sha256": sha256(json.dumps(raw_draft, sort_keys=True,
                   separators=(",", ":")).encode()).hexdigest(),
               "updated_at": datetime.now(timezone.utc).isoformat(), "draft": raw_draft}
        raw = (json.dumps(row, sort_keys=True, indent=2) + "\n").encode()
        if len(raw) > 16384 or self.root.is_symlink():
            raise ValueError("Application context is oversized or unsafe.")
        path = self._path(draft.target_id)
        if path.is_symlink():
            raise ValueError("Linked application context is unsupported.")
        temporary = self.root / (".application-context-" + secrets.token_hex(16) + ".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()
        return row
