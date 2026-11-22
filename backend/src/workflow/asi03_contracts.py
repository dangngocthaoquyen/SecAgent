"""Operator-reviewed ASI03 context for imported response claims."""

from hashlib import sha256
from pathlib import Path
from threading import RLock
from typing import Literal
from uuid import uuid4
import json
import re

from pydantic import BaseModel, ConfigDict, Field, model_validator

from reporting.artifacts import ArchiveReader, _no_links, _json
from workflow.batch import _write_atomic
from workflow.dataset_repository import DatasetRepository


class ASI03ContractDraft(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_dataset_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    source_testcase_id: str = Field(pattern=r"^import-[a-f0-9]{24}$")
    target_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    evaluation_scope: Literal["identity_claim_response", "privileged_action"] | None = None
    legitimate_agent_identity: str | None = Field(default=None, max_length=500)
    allowed_roles: list[str] = Field(default_factory=list, max_length=20)
    legitimate_user_goal: str | None = Field(default=None, max_length=4000)
    attacker_objective: str | None = Field(default=None, max_length=4000)
    prohibited_identity_claim: str | None = Field(default=None, max_length=500)
    prohibited_authority_claim: str | None = Field(default=None, max_length=500)
    attack_surface: str | None = Field(default=None, max_length=500)
    delivery_surface: Literal["direct_chat", "untrusted_document", "tool_result", "session_transition"] | None = None
    required_evidence: list[Literal["complete_response_text", "independent_agent_action_trace", "verified_authorization_baseline"]] = Field(default_factory=list, max_length=3)
    expected_security_boundary: str | None = Field(default=None, max_length=4000)


def _hash(value: object) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


class ASI03ContractStore:
    """Separate, integrity-checked records under the managed operator data root."""

    def __init__(self, datasets: DatasetRepository, catalog):
        if not hasattr(catalog, "data_dir"):
            raise ValueError("ASI03 contracts require a managed target catalog.")
        self.datasets, self.catalog = datasets, catalog
        self.root = Path(catalog.data_dir) / "asi03-contracts"
        _no_links(self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.reader = ArchiveReader(self.root)
        self.lock = RLock()

    def _path(self, contract_id: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{32}", contract_id):
            raise ValueError("Invalid contract identifier.")
        return self.reader.path(f"{contract_id}.json")

    def _binding(self, draft: ASI03ContractDraft) -> dict:
        dataset = self.datasets.get_dataset(draft.source_dataset_id)
        if dataset is None:
            raise ValueError("asi03_dataset_unavailable")
        case = next((c for c in dataset.testcases if c.internal_id == draft.source_testcase_id), None)
        if case is None:
            raise ValueError("asi03_testcase_unavailable")
        target = self.catalog._targets.get(draft.target_id)
        if target is None:
            raise ValueError("asi03_target_unavailable")
        return {
            "dataset_sha256": dataset.file_sha256,
            "dataset_content_sha256": dataset.content_sha256,
            "source_testcase_id": case.testcase_id,
            "source_case_sha256": _hash(case.source_case),
            "source_input_sha256": case.prompt_sha256,
            "target_profile_revision": self.catalog._revisions[target.id],
            "target_endpoint_sha256": sha256(target.endpoint.encode()).hexdigest(),
            "target_model": target.default_model,
            "target_protocol": target.protocol,
            "target_policy_ref": self.catalog._config.policy_ref,
        }

    @staticmethod
    def _fields(draft: ASI03ContractDraft) -> list[str]:
        missing = []
        if draft.evaluation_scope is None:
            missing.append("asi03_scope_required")
        for key in ("legitimate_agent_identity", "legitimate_user_goal", "attacker_objective",
                    "attack_surface", "expected_security_boundary"):
            if not (getattr(draft, key) or "").strip():
                missing.append(f"asi03_{key}_required")
        if not draft.allowed_roles or any(not role.strip() for role in draft.allowed_roles):
            missing.append("asi03_allowed_roles_required")
        if draft.evaluation_scope == "identity_claim_response" and not (draft.prohibited_identity_claim or "").strip() and not (draft.prohibited_authority_claim or "").strip():
            missing.append("asi03_prohibited_claim_required")
        if draft.delivery_surface is None:
            missing.append("asi03_delivery_surface_required")
        if draft.evaluation_scope == "identity_claim_response":
            if "complete_response_text" not in draft.required_evidence:
                missing.append("asi03_response_observation_required")
        if draft.evaluation_scope == "privileged_action":
            if not {"independent_agent_action_trace", "verified_authorization_baseline"}.issubset(draft.required_evidence):
                missing.append("asi03_action_evidence_required")
        return missing

    def create(self, draft: ASI03ContractDraft) -> dict:
        with self.lock:
            binding = self._binding(draft)
            material = {"contract_version": "1.0.0", "asi_category": "ASI03",
                        "draft": draft.model_dump(mode="json"), "binding": binding}
            record = {**material, "contract_id": uuid4().hex, "revision_sha256": _hash(material),
                      "review_status": "draft", "reviewed_revision_sha256": None}
            path = self._path(record["contract_id"])
            if path.exists():
                raise ValueError("asi03_contract_collision")
            _write_atomic(path, record)
            return self.status(record)

    def load(self, contract_id: str) -> dict | None:
        try:
            raw = self.reader.read(self._path(contract_id), 32768)
            if raw is None:
                return None
            record = _json(raw)
            if (set(record) != {"contract_version", "asi_category", "draft", "binding", "contract_id",
                                "revision_sha256", "review_status", "reviewed_revision_sha256"}
                    or record["contract_id"] != contract_id or record["contract_version"] != "1.0.0"
                    or record["asi_category"] != "ASI03"
                    or record["review_status"] not in {"draft", "reviewed"}):
                return None
            draft = ASI03ContractDraft.model_validate(record["draft"])
            material = {key: record[key] for key in ("contract_version", "asi_category", "draft", "binding")}
            if (record["revision_sha256"] != _hash(material)
                    or (record["review_status"] == "reviewed" and
                        record["reviewed_revision_sha256"] != record["revision_sha256"])):
                return None
            return record
        except (OSError, ValueError, TypeError, KeyError):
            return None

    def status(self, record: dict) -> dict:
        draft = ASI03ContractDraft.model_validate(record["draft"])
        blockers = self._fields(draft)
        try:
            if self._binding(draft) != record["binding"]:
                blockers.append("asi03_contract_stale")
            target = self.catalog._targets[draft.target_id]
            if not target.reviewed:
                blockers.append("asi03_target_not_reviewed")
            if target.protocol != "openai-chat":
                blockers.append("asi03_response_adapter_unavailable")
        except (ValueError, KeyError):
            blockers.append("asi03_contract_stale")
        if record["review_status"] != "reviewed":
            blockers.append("asi03_contract_not_reviewed")
        if draft.delivery_surface != "direct_chat":
            blockers.append("asi03_delivery_surface_unsupported")
        if draft.evaluation_scope == "privileged_action":
            blockers.append("asi03_action_runtime_unavailable")
        blockers = sorted(set(blockers))
        lifecycle = ("stale" if "asi03_contract_stale" in blockers else
                     "reviewed" if record["review_status"] == "reviewed" else "draft")
        return {**record, "review_status": lifecycle, "readiness_blockers": blockers,
                "response_contract_ready": lifecycle == "reviewed" and not blockers
                and draft.evaluation_scope == "identity_claim_response"}

    def review(self, contract_id: str, expected_revision: str, *, confirmed: bool) -> dict:
        with self.lock:
            record = self.load(contract_id)
            if record is None:
                raise ValueError("asi03_contract_unavailable")
            if not confirmed or record["revision_sha256"] != expected_revision:
                raise ValueError("asi03_review_confirmation_or_revision_required")
            current = self.status(record)
            blockers = [b for b in current["readiness_blockers"] if b not in {
                "asi03_contract_not_reviewed", "asi03_action_runtime_unavailable"}]
            if blockers:
                raise ValueError(blockers[0])
            record["review_status"] = "reviewed"
            record["reviewed_revision_sha256"] = record["revision_sha256"]
            _write_atomic(self._path(contract_id), record)
            return self.status(record)

    def for_case(self, dataset_id: str, case_id: str, target_id: str) -> dict | None:
        with self.lock:
            matches = []
            for path in sorted(self.root.glob("*.json"), key=lambda p: p.stat().st_mtime_ns):
                record = self.load(path.stem)
                if record is None:
                    continue
                draft = record["draft"]
                if (draft["source_dataset_id"], draft["source_testcase_id"], draft["target_id"]) == (dataset_id, case_id, target_id):
                    matches.append(self.status(record))
            # A new draft supersedes an older review; it cannot silently inherit it.
            return matches[-1] if matches else None


class ASI03TargetPolicyDraft(BaseModel):
    """Reviewed identity boundary shared by direct-chat cases on one target."""
    model_config = ConfigDict(extra="forbid")
    target_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    legitimate_agent_identity: str = Field(min_length=1, max_length=500)
    allowed_roles: list[str] = Field(min_length=1, max_length=20)
    prohibited_identity_claim: str | None = Field(default=None, max_length=500)
    prohibited_authority_claim: str | None = Field(default=None, max_length=500)
    expected_security_boundary: str = Field(min_length=1, max_length=4000)
    evaluation_scope: Literal["identity_claim_response"] = "identity_claim_response"
    delivery_surface: Literal["direct_chat"] = "direct_chat"

    @model_validator(mode="after")
    def meaningful_policy(self):
        if (not self.legitimate_agent_identity.strip() or not self.expected_security_boundary.strip()
                or any(not role.strip() for role in self.allowed_roles)
                or not any((claim or "").strip() for claim in (
                    self.prohibited_identity_claim, self.prohibited_authority_claim))):
            raise ValueError("asi03_policy_fields_required")
        return self


class ASI03TargetPolicyStore:
    """Operator-owned policy revisions; a newer draft supersedes older review."""
    def __init__(self, catalog):
        if not hasattr(catalog, "data_dir"):
            raise ValueError("ASI03 policies require a managed target catalog.")
        self.catalog = catalog
        self.root = Path(catalog.data_dir) / "asi03-target-policies"
        _no_links(self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.reader = ArchiveReader(self.root)
        self.lock = RLock()

    def _path(self, policy_id: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{32}", policy_id):
            raise ValueError("Invalid policy identifier.")
        return self.reader.path(f"{policy_id}.json")

    def _binding(self, draft: ASI03TargetPolicyDraft) -> dict:
        target = self.catalog._targets.get(draft.target_id)
        if target is None:
            raise ValueError("asi03_target_unavailable")
        return {"target_profile_revision": self.catalog._revisions[target.id],
                "target_endpoint_sha256": sha256(target.endpoint.encode()).hexdigest(),
                "target_model": target.default_model, "target_protocol": target.protocol,
                "target_policy_ref": self.catalog._config.policy_ref}

    def create(self, draft: ASI03TargetPolicyDraft) -> dict:
        with self.lock:
            material = {"policy_version": "1.0.0", "draft": draft.model_dump(mode="json"),
                        "binding": self._binding(draft)}
            record = {**material, "policy_id": uuid4().hex, "revision_sha256": _hash(material),
                      "review_status": "draft", "reviewed_revision_sha256": None}
            _write_atomic(self._path(record["policy_id"]), record)
            return self.status(record)

    def load(self, policy_id: str) -> dict | None:
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
            ASI03TargetPolicyDraft.model_validate(record["draft"])
            material = {key: record[key] for key in ("policy_version", "draft", "binding")}
            if (record["revision_sha256"] != _hash(material)
                    or (record["review_status"] == "reviewed" and
                        record["reviewed_revision_sha256"] != record["revision_sha256"])):
                return None
            return record
        except (OSError, ValueError, TypeError, KeyError):
            return None

    def status(self, record: dict) -> dict:
        draft = ASI03TargetPolicyDraft.model_validate(record["draft"])
        blockers = []
        try:
            if self._binding(draft) != record["binding"]:
                blockers.append("asi03_policy_stale")
            target = self.catalog._targets[draft.target_id]
            if not target.reviewed:
                blockers.append("asi03_target_not_reviewed")
            if target.protocol != "openai-chat":
                blockers.append("asi03_response_adapter_unavailable")
        except (ValueError, KeyError):
            blockers.append("asi03_policy_stale")
        if record["review_status"] != "reviewed":
            blockers.append("asi03_policy_not_reviewed")
        return {**record, "review_status": "stale" if "asi03_policy_stale" in blockers
                else record["review_status"], "readiness_blockers": blockers,
                "response_policy_ready": not blockers}

    def review(self, policy_id: str, expected_revision: str, *, confirmed: bool) -> dict:
        with self.lock:
            record = self.load(policy_id)
            if record is None:
                raise ValueError("asi03_policy_unavailable")
            if not confirmed or record["revision_sha256"] != expected_revision:
                raise ValueError("asi03_policy_review_confirmation_or_revision_required")
            blockers = [b for b in self.status(record)["readiness_blockers"]
                        if b != "asi03_policy_not_reviewed"]
            if blockers:
                raise ValueError(blockers[0])
            record["review_status"] = "reviewed"
            record["reviewed_revision_sha256"] = record["revision_sha256"]
            _write_atomic(self._path(policy_id), record)
            return self.status(record)

    def for_target(self, target_id: str) -> dict | None:
        with self.lock:
            matches = []
            for path in sorted(self.root.glob("*.json"), key=lambda p: (p.stat().st_mtime_ns, p.name)):
                record = self.load(path.stem)
                if record and record["draft"]["target_id"] == target_id:
                    matches.append(self.status(record))
            return matches[-1] if matches else None
