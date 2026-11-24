"""Server-owned MCP Tool Catalog store for generic capability onboarding (Stage 3D.6)."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import re
from threading import RLock
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from reporting.artifacts import ArchiveReader, _json, _no_links
from targets.runtimes import ReviewedToolSpec, compute_tool_catalog_sha256
from workflow.asi03_contracts import _hash
from workflow.batch import _write_atomic
from workflow.models import Identifier


class McpToolCatalogDraft(BaseModel):
    """Operator-selected or manually reviewed MCP tool schemas for one MCP server."""

    model_config = ConfigDict(extra="forbid")

    mcp_target_id: Identifier
    discovery_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    catalog_name: str = Field(default="Reviewed MCP Tool Catalog", min_length=1, max_length=128)
    reviewed_tools: tuple[ReviewedToolSpec, ...] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def validate_unique_tools(self):
        if not self.catalog_name.strip():
            raise ValueError("mcp_catalog_name_required")
        names = [tool.name for tool in self.reviewed_tools]
        if len(set(names)) != len(names):
            raise ValueError("mcp_catalog_duplicate_tool_name")
        return self


class McpToolCatalogStore:
    """Server-owned immutable store of reviewed MCP Tool Catalog revisions."""

    def __init__(self, catalog, *, discovery=None) -> None:
        if not hasattr(catalog, "data_dir"):
            raise ValueError("MCP Tool Catalog store requires a managed target catalog.")
        self.catalog = catalog
        self.discovery = discovery
        self.root = Path(catalog.data_dir) / "mcp-tool-catalogs"
        _no_links(self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.reader = ArchiveReader(self.root)
        self.lock = RLock()

    def _path(self, catalog_id: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{32}", catalog_id):
            raise ValueError("mcp_catalog_invalid_id")
        return self.reader.path(f"{catalog_id}.json")

    def _catalog_snapshot(self, draft: McpToolCatalogDraft) -> dict:
        mcp = self.catalog._targets.get(draft.mcp_target_id)
        if mcp is None:
            raise ValueError("mcp_catalog_target_unavailable")
        if mcp.protocol != "mcp-jsonrpc":
            raise ValueError("mcp_catalog_protocol_mismatch")
        discovery_manifest_sha256: str | None = None
        if draft.discovery_id is not None and self.discovery is not None:
            try:
                disc = self.discovery.load(draft.discovery_id)
            except Exception as exc:
                raise ValueError("mcp_catalog_discovery_unavailable") from exc
            if disc.get("canonical_endpoint") != mcp.endpoint:
                raise ValueError("mcp_catalog_discovery_endpoint_mismatch")
            discovery_manifest_sha256 = disc.get("advertised_tool_manifest_sha256")
        return {
            "mcp_target_profile_revision": self.catalog._revisions[mcp.id],
            "mcp_endpoint_sha256": sha256(mcp.endpoint.encode("utf-8")).hexdigest(),
            "discovery_id": draft.discovery_id,
            "discovery_manifest_sha256": discovery_manifest_sha256,
            "target_policy_ref": self.catalog._config.policy_ref,
            "tool_catalog_sha256": compute_tool_catalog_sha256(draft.reviewed_tools),
            "tool_names": [tool.name for tool in draft.reviewed_tools],
        }

    def create(self, draft: McpToolCatalogDraft) -> dict:
        with self.lock:
            material = {
                "catalog_version": "1.0.0",
                "draft": draft.model_dump(mode="json"),
                "binding": self._catalog_snapshot(draft),
            }
            record = {
                **material,
                "catalog_id": uuid4().hex,
                "revision_sha256": _hash(material),
                "review_status": "draft",
                "reviewed_revision_sha256": None,
            }
            _write_atomic(self._path(record["catalog_id"]), record)
            return self.status(record)

    def create_from_discovery(
        self,
        *,
        mcp_target_id: str,
        discovery_id: str,
        selected_tool_names: tuple[str, ...] | list[str] | None = None,
        catalog_name: str = "Reviewed MCP Tool Catalog",
    ) -> dict:
        if self.discovery is None:
            raise ValueError("mcp_catalog_discovery_unavailable")
        try:
            manifest = self.discovery.load_mcp_capabilities(discovery_id)
        except Exception as exc:
            raise ValueError("mcp_catalog_discovery_unavailable") from exc
        mcp = self.catalog._targets.get(mcp_target_id)
        if mcp is None:
            raise ValueError("mcp_catalog_target_unavailable")
        if mcp.protocol != "mcp-jsonrpc":
            raise ValueError("mcp_catalog_protocol_mismatch")
        if manifest.get("source_endpoint") != mcp.endpoint:
            raise ValueError("mcp_catalog_discovery_endpoint_mismatch")
        tools_by_name = {item["name"]: item for item in manifest.get("tools", []) if isinstance(item, dict) and item.get("name")}
        if selected_tool_names is not None:
            chosen = []
            for name in selected_tool_names:
                item = tools_by_name.get(name)
                if item is None:
                    raise ValueError("mcp_catalog_selected_tool_not_discovered")
                if not item.get("schema_compatible"):
                    raise ValueError(item.get("schema_error") or "mcp_tool_schema_incompatible")
                chosen.append(item)
        else:
            chosen = [item for item in manifest.get("tools", []) if item.get("schema_compatible")]
        if not chosen:
            raise ValueError("mcp_catalog_no_compatible_tools")
        specs = tuple(
            ReviewedToolSpec(
                name=item["name"],
                description=item.get("description") or f"MCP tool {item['name']}",
                input_schema=item["input_schema"],
            )
            for item in chosen
        )
        draft = McpToolCatalogDraft(
            mcp_target_id=mcp_target_id,
            discovery_id=discovery_id,
            catalog_name=catalog_name,
            reviewed_tools=specs,
        )
        return self.create(draft)

    def load(self, catalog_id: str) -> dict | None:
        try:
            raw = self.reader.read(self._path(catalog_id), 131072)
            if raw is None:
                return None
            record = _json(raw)
            if (
                set(record) != {
                    "catalog_version",
                    "draft",
                    "binding",
                    "catalog_id",
                    "revision_sha256",
                    "review_status",
                    "reviewed_revision_sha256",
                }
                or record["catalog_id"] != catalog_id
                or record["catalog_version"] != "1.0.0"
                or record["review_status"] not in {"draft", "reviewed"}
            ):
                return None
            McpToolCatalogDraft.model_validate(record["draft"])
            material = {key: record[key] for key in ("catalog_version", "draft", "binding")}
            if (
                record["revision_sha256"] != _hash(material)
                or (
                    record["review_status"] == "reviewed"
                    and record["reviewed_revision_sha256"] != record["revision_sha256"]
                )
            ):
                return None
            return record
        except (OSError, ValueError, TypeError, KeyError):
            return None

    def status(self, record: dict) -> dict:
        draft = McpToolCatalogDraft.model_validate(record["draft"])
        blockers: list[str] = []
        try:
            if self._catalog_snapshot(draft) != record["binding"]:
                blockers.append("mcp_catalog_stale")
            mcp = self.catalog._targets[draft.mcp_target_id]
            if not mcp.reviewed:
                blockers.append("mcp_catalog_mcp_target_not_reviewed")
        except (ValueError, KeyError):
            blockers.append("mcp_catalog_stale")
        if record["review_status"] != "reviewed":
            blockers.append("mcp_catalog_not_reviewed")
        return {
            **record,
            "review_status": "stale" if "mcp_catalog_stale" in blockers else record["review_status"],
            "readiness_blockers": blockers,
            "catalog_ready": not blockers,
        }

    def review(self, catalog_id: str, expected_revision: str, *, confirmed: bool) -> dict:
        with self.lock:
            record = self.load(catalog_id)
            if record is None:
                raise ValueError("mcp_catalog_unavailable")
            if not confirmed or record["revision_sha256"] != expected_revision:
                raise ValueError("mcp_catalog_review_confirmation_or_revision_required")
            blockers = [
                b for b in self.status(record)["readiness_blockers"]
                if b != "mcp_catalog_not_reviewed"
            ]
            if blockers:
                raise ValueError(blockers[0])
            record["review_status"] = "reviewed"
            record["reviewed_revision_sha256"] = record["revision_sha256"]
            _write_atomic(self._path(catalog_id), record)
            return self.status(record)

    def list_all(self) -> list[dict]:
        with self.lock:
            items = []
            for path in sorted(self.root.glob("*.json"), key=lambda p: (p.stat().st_mtime_ns, p.name)):
                record = self.load(path.stem)
                if record:
                    items.append(self.status(record))
            return items

    def for_target(self, mcp_target_id: str) -> list[dict]:
        return [item for item in self.list_all() if item["draft"]["mcp_target_id"] == mcp_target_id]
