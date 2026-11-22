"""Reviewed target response boundary for imported ASI05 command-artifact cases."""
from hashlib import sha256
from pathlib import Path
from threading import RLock
from typing import Literal
from uuid import uuid4
import re

from pydantic import BaseModel, ConfigDict, Field, model_validator

from reporting.artifacts import ArchiveReader, _json, _no_links
from workflow.asi03_contracts import _hash
from workflow.batch import _write_atomic


class ASI05PolicyDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    prohibited_command_behavior: str = Field(min_length=1, max_length=2000)
    allowed_benign_context: str = Field(min_length=1, max_length=2000)
    expected_response_boundary: str = Field(min_length=1, max_length=2000)
    evaluation_scope: Literal["response_command_artifact"] = "response_command_artifact"
    delivery_surface: Literal["direct_chat"] = "direct_chat"

    @model_validator(mode="after")
    def meaningful(self):
        if any(not value.strip() for value in (self.prohibited_command_behavior,
                self.allowed_benign_context, self.expected_response_boundary)):
            raise ValueError("asi05_policy_fields_required")
        return self


class ASI05PolicyStore:
    """Immutable revisions under the managed operator data root."""
    def __init__(self, catalog):
        if not hasattr(catalog, "data_dir"):
            raise ValueError("ASI05 policy requires a managed target catalog.")
        self.catalog = catalog
        self.root = Path(catalog.data_dir) / "asi05-response-policies"
        _no_links(self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.reader = ArchiveReader(self.root)
        self.lock = RLock()

    def _path(self, policy_id):
        if not re.fullmatch(r"[a-f0-9]{32}", policy_id):
            raise ValueError("Invalid policy identifier.")
        return self.reader.path(f"{policy_id}.json")

    def _binding(self, draft):
        target = self.catalog._targets.get(draft.target_id)
        if target is None:
            raise ValueError("asi05_target_unavailable")
        return {"target_profile_revision": self.catalog._revisions[target.id],
                "target_endpoint_sha256": sha256(target.endpoint.encode()).hexdigest(),
                "target_model": target.default_model, "target_protocol": target.protocol,
                "target_policy_ref": self.catalog._config.policy_ref}

    def create(self, draft: ASI05PolicyDraft):
        with self.lock:
            material = {"policy_version": "1.0.0", "draft": draft.model_dump(mode="json"),
                        "binding": self._binding(draft)}
            record = {**material, "policy_id": uuid4().hex, "revision_sha256": _hash(material),
                      "review_status": "draft", "reviewed_revision_sha256": None}
            _write_atomic(self._path(record["policy_id"]), record)
            return self.status(record)

    def load(self, policy_id):
        try:
            raw = self.reader.read(self._path(policy_id), 32768)
            if raw is None:
                return None
            record = _json(raw)
            if (set(record) != {"policy_version", "draft", "binding", "policy_id",
                                "revision_sha256", "review_status", "reviewed_revision_sha256"}
                    or record["policy_id"] != policy_id or record["policy_version"] != "1.0.0"
                    or record["review_status"] not in {"draft", "reviewed"}):
                return None
            ASI05PolicyDraft.model_validate(record["draft"])
            material = {key: record[key] for key in ("policy_version", "draft", "binding")}
            if (record["revision_sha256"] != _hash(material)
                    or (record["review_status"] == "reviewed" and
                        record["reviewed_revision_sha256"] != record["revision_sha256"])):
                return None
            return record
        except (OSError, ValueError, TypeError, KeyError):
            return None

    def status(self, record):
        draft = ASI05PolicyDraft.model_validate(record["draft"])
        blockers = []
        try:
            if self._binding(draft) != record["binding"]:
                blockers.append("asi05_policy_stale")
            target = self.catalog._targets[draft.target_id]
            if not target.reviewed:
                blockers.append("asi05_target_not_reviewed")
            if target.protocol != "openai-chat":
                blockers.append("asi05_response_adapter_unavailable")
        except (ValueError, KeyError):
            blockers.append("asi05_policy_stale")
        if record["review_status"] != "reviewed":
            blockers.append("asi05_policy_not_reviewed")
        return {**record, "review_status": "stale" if "asi05_policy_stale" in blockers
                else record["review_status"], "readiness_blockers": blockers,
                "response_policy_ready": not blockers}

    def review(self, policy_id, expected_revision, *, confirmed):
        with self.lock:
            record = self.load(policy_id)
            if record is None:
                raise ValueError("asi05_policy_unavailable")
            if not confirmed or record["revision_sha256"] != expected_revision:
                raise ValueError("asi05_policy_review_confirmation_or_revision_required")
            blockers = [b for b in self.status(record)["readiness_blockers"]
                        if b != "asi05_policy_not_reviewed"]
            if blockers:
                raise ValueError(blockers[0])
            record["review_status"] = "reviewed"
            record["reviewed_revision_sha256"] = record["revision_sha256"]
            _write_atomic(self._path(policy_id), record)
            return self.status(record)

    def for_target(self, target_id):
        with self.lock:
            matches = []
            for path in sorted(self.root.glob("*.json"), key=lambda p: (p.stat().st_mtime_ns, p.name)):
                record = self.load(path.stem)
                if record and record["draft"]["target_id"] == target_id:
                    matches.append(self.status(record))
            return matches[-1] if matches else None
