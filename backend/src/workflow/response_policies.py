"""Unified operator-reviewed response policy store for ASI01, ASI02, ASI03, and ASI05."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from threading import RLock
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


PolicyCategory = Literal[
    "goal_hijacking",
    "tool_misuse",
    "identity_privilege_abuse",
    "unexpected_code_execution",
]

ASI_CATEGORY_ALIASES: dict[str, PolicyCategory] = {
    "ASI01": "goal_hijacking",
    "goal_hijacking": "goal_hijacking",
    "ASI02": "tool_misuse",
    "tool_misuse": "tool_misuse",
    "ASI03": "identity_privilege_abuse",
    "identity_privilege_abuse": "identity_privilege_abuse",
    "ASI05": "unexpected_code_execution",
    "unexpected_code_execution": "unexpected_code_execution",
}

DEFAULT_EVALUATION_SCOPES: dict[PolicyCategory, str] = {
    "goal_hijacking": "goal_hijack_response",
    "tool_misuse": "tool_intent_response",
    "identity_privilege_abuse": "identity_claim_response",
    "unexpected_code_execution": "response_command_artifact",
}

POLICY_REVISION_KEYS: dict[PolicyCategory, str] = {
    "goal_hijacking": "asi01_policy_revision_sha256",
    "tool_misuse": "asi02_policy_revision_sha256",
    "identity_privilege_abuse": "asi03_policy_revision_sha256",
    "unexpected_code_execution": "asi05_policy_revision_sha256",
}

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def canonical_policy_hash(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def normalize_policy_category(raw: str) -> PolicyCategory:
    cleaned = raw.strip()
    mapped = ASI_CATEGORY_ALIASES.get(cleaned) or ASI_CATEGORY_ALIASES.get(cleaned.upper())
    if mapped is None:
        raise ValueError(f"Unsupported ASI policy category: {raw!r}")
    return mapped


class ResponsePolicyDraft(BaseModel):
    """Target-scoped operator-authored policy fields prior to cryptographic freeze."""

    model_config = ConfigDict(extra="forbid")

    target_id: str = Field(min_length=1, max_length=128)
    category: PolicyCategory
    evaluation_scope: str = Field(min_length=1, max_length=128)

    @field_validator("category", mode="before")
    @classmethod
    def _normalize_category(cls, value: Any) -> str:
        if isinstance(value, str):
            return normalize_policy_category(value)
        return value
    prohibited_behavior: str = Field(min_length=1, max_length=4000)
    allowed_benign_context: str = Field(min_length=1, max_length=4000)
    expected_response_boundary: str = Field(min_length=1, max_length=4000)
    delivery_surface: str = Field(default="direct_chat", min_length=1, max_length=256)
    extra_rules: dict[str, Any] = Field(default_factory=dict)


class ReviewedResponsePolicy(BaseModel):
    """Frozen, operator-reviewed response policy record bound by SHA-256 revision."""

    model_config = ConfigDict(extra="forbid")

    policy_id: str
    target_id: str
    category: PolicyCategory
    revision_sha256: str
    review_status: Literal["draft", "reviewed"]
    reviewed_by: str | None = None
    reviewed_at: str | None = None
    created_at: str
    draft: ResponsePolicyDraft


def validate_policy_context_revision(trusted_context: dict[str, Any], category: str) -> tuple[bool, str]:
    """Validate revision SHA-256 and explicit review status inside trusted_context."""
    try:
        normalized = normalize_policy_category(category)
    except ValueError:
        return True, ""
    rev_key = POLICY_REVISION_KEYS[normalized]
    revision = trusted_context.get(rev_key)
    if normalized == "identity_privilege_abuse" and revision is None:
        revision = trusted_context.get("asi03_contract_revision_sha256")
    if revision is not None:
        if not isinstance(revision, str) or not _SHA256_RE.fullmatch(revision):
            return False, f"{rev_key} must be a valid 64-character lowercase SHA-256 digest."
    review_status = trusted_context.get("policy_review_status")
    if review_status is not None and review_status != "reviewed":
        return False, "Policy review_status must be 'reviewed' before evaluation."
    return True, ""


class ResponsePolicyStore:
    """Thread-safe JSON store for target-scoped ASI01/ASI02/ASI03/ASI05 response policies."""

    def __init__(self, root: str | Path) -> None:
        self._root = Path(root).resolve()
        self._root.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()

    def _path(self, policy_id: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", policy_id):
            raise ValueError("Invalid policy identifier.")
        return self._root / f"{policy_id}.json"

    def save_draft(self, draft: ResponsePolicyDraft | dict[str, Any]) -> ReviewedResponsePolicy:
        model = draft if isinstance(draft, ResponsePolicyDraft) else ResponsePolicyDraft.model_validate(draft)
        now = datetime.now(timezone.utc).isoformat()
        policy_id = f"pol-{model.category[:8]}-{uuid4().hex[:12]}"
        revision = canonical_policy_hash(model.model_dump(mode="json"))
        record = ReviewedResponsePolicy(
            policy_id=policy_id,
            target_id=model.target_id,
            category=model.category,
            revision_sha256=revision,
            review_status="draft",
            created_at=now,
            draft=model,
        )
        with self._lock:
            self._path(policy_id).write_text(
                json.dumps(record.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
        return record

    def review(self, policy_id: str, *, reviewer: str, expected_revision_sha256: str) -> ReviewedResponsePolicy:
        if not reviewer.strip():
            raise ValueError("Reviewer identity must not be blank.")
        with self._lock:
            record = self.get(policy_id)
            computed = canonical_policy_hash(record.draft.model_dump(mode="json"))
            if computed != record.revision_sha256 or computed != expected_revision_sha256:
                raise ValueError("Policy revision mismatch; review rejected.")
            updated = record.model_copy(
                update={
                    "review_status": "reviewed",
                    "reviewed_by": reviewer.strip(),
                    "reviewed_at": datetime.now(timezone.utc).isoformat(),
                }
            )
            self._path(policy_id).write_text(
                json.dumps(updated.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            return updated

    def get(self, policy_id: str) -> ReviewedResponsePolicy:
        path = self._path(policy_id)
        if not path.is_file():
            raise FileNotFoundError(f"Response policy not found: {policy_id}")
        raw = json.loads(path.read_text(encoding="utf-8"))
        return ReviewedResponsePolicy.model_validate(raw)

    def require_reviewed(self, policy_id: str, *, target_id: str | None = None) -> ReviewedResponsePolicy:
        record = self.get(policy_id)
        if record.review_status != "reviewed":
            raise ValueError(f"Policy '{policy_id}' has not been reviewed.")
        computed = canonical_policy_hash(record.draft.model_dump(mode="json"))
        if computed != record.revision_sha256:
            raise ValueError(f"Policy '{policy_id}' revision integrity check failed.")
        if target_id is not None and record.target_id != target_id:
            raise ValueError(f"Policy '{policy_id}' is bound to target '{record.target_id}', not '{target_id}'.")
        return record

    def list_for_target(
        self, target_id: str, *, category: str | None = None
    ) -> list[ReviewedResponsePolicy]:
        normalized_cat = normalize_policy_category(category) if category else None
        results: list[ReviewedResponsePolicy] = []
        with self._lock:
            for file in sorted(self._root.glob("*.json")):
                record = ReviewedResponsePolicy.model_validate(
                    json.loads(file.read_text(encoding="utf-8"))
                )
                if record.target_id == target_id and (normalized_cat is None or record.category == normalized_cat):
                    results.append(record)
        return results

    def to_trusted_context(self, policy: ReviewedResponsePolicy) -> dict[str, Any]:
        """Convert a verified reviewed policy into HybridEvaluator trusted_context."""
        verified = self.require_reviewed(policy.policy_id, target_id=policy.target_id)
        rev_key = POLICY_REVISION_KEYS[verified.category]
        context: dict[str, Any] = {
            "evaluation_scope": verified.draft.evaluation_scope,
            "context_source": "reviewed_policy",
            "policy_id": verified.policy_id,
            "reviewed_policy_id": verified.policy_id,
            "reviewed_policy_revision_sha256": verified.revision_sha256,
            rev_key: verified.revision_sha256,
            "policy_review_status": verified.review_status,
            "delivery_surface": verified.draft.delivery_surface,
            "allowed_benign_context": verified.draft.allowed_benign_context,
            "expected_response_boundary": verified.draft.expected_response_boundary,
            **verified.draft.extra_rules,
        }
        if verified.category == "goal_hijacking":
            context.setdefault("original_goal", verified.draft.allowed_benign_context)
            context.setdefault("attacker_goal", verified.draft.prohibited_behavior)
            context.setdefault("trust_boundary", verified.draft.expected_response_boundary)
            context["prohibited_goal_behavior"] = verified.draft.prohibited_behavior
        elif verified.category == "tool_misuse":
            context["prohibited_tool_behavior"] = verified.draft.prohibited_behavior
        elif verified.category == "identity_privilege_abuse":
            context.setdefault("prohibited_identity_claim", verified.draft.prohibited_behavior)
            context.setdefault("prohibited_authority_claim", verified.draft.prohibited_behavior)
            context["asi03_policy_id"] = verified.policy_id
        elif verified.category == "unexpected_code_execution":
            context["prohibited_command_behavior"] = verified.draft.prohibited_behavior
            context["asi05_policy_id"] = verified.policy_id
        return context


def main(argv: list[str] | None = None) -> int:
    """CLI for inspecting and explicitly reviewing response policies by exact SHA-256."""
    parser = argparse.ArgumentParser(description="Inspect and explicitly approve SecAgent response policies.")
    sub = parser.add_subparsers(dest="command", required=True)

    list_p = sub.add_parser("list", help="List policy drafts and reviewed policies.")
    list_p.add_argument("--policy-dir", default="configs/response_policies")
    list_p.add_argument("--target-id", default=None)

    show_p = sub.add_parser("show", help="Show full JSON contents and revision SHA-256 of one policy.")
    show_p.add_argument("--policy-dir", default="configs/response_policies")
    show_p.add_argument("--policy-id", required=True)

    rev_p = sub.add_parser("review", help="Approve one draft policy by exact expected revision SHA-256.")
    rev_p.add_argument("--policy-dir", default="configs/response_policies")
    rev_p.add_argument("--policy-id", required=True)
    rev_p.add_argument("--expected-revision", required=True)
    rev_p.add_argument("--reviewer", required=True)
    rev_p.add_argument("--confirm", action="store_true", help="Required explicit confirmation flag.")

    args = parser.parse_args(argv)
    store = ResponsePolicyStore(args.policy_dir)

    if args.command == "list":
        rows = []
        for file in sorted(Path(args.policy_dir).glob("*.json")):
            rec = store.get(file.stem)
            if args.target_id and rec.target_id != args.target_id:
                continue
            rows.append({
                "policy_id": rec.policy_id,
                "target_id": rec.target_id,
                "category": rec.category,
                "evaluation_scope": rec.draft.evaluation_scope,
                "review_status": rec.review_status,
                "revision_sha256": rec.revision_sha256,
                "reviewed_by": rec.reviewed_by,
            })
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return 0

    if args.command == "show":
        rec = store.get(args.policy_id)
        print(json.dumps(rec.model_dump(mode="json"), indent=2, ensure_ascii=False))
        return 0

    if args.command == "review":
        if not args.confirm:
            print("Error: --confirm is required to approve a policy.", file=sys.stderr)
            return 2
        updated = store.review(
            args.policy_id,
            reviewer=args.reviewer,
            expected_revision_sha256=args.expected_revision,
        )
        print(json.dumps(updated.model_dump(mode="json"), indent=2, ensure_ascii=False))
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
