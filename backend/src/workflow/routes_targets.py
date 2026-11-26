"""Target, discovery, application-context, and evidence-source routes for Workflow API."""

from contextlib import nullcontext
import json
from pathlib import Path
import shutil
from typing import Any, Literal

from flask import jsonify, request
from pydantic import Field, ValidationError

from workflow.application_context import SaveApplicationContext
from workflow.catalog import CatalogError, read_json
from workflow.discovery import DiscoveryError, DiscoveryRequest
from workflow.evidence_sources import CollectEvidenceSource, EvidenceSourceError, SaveEvidenceSource
from workflow.management import (
    DeleteTargetRequest,
    ManagedProfile,
    ReviewProfile,
    SaveProfile,
)
from workflow.models import ClosedModel, ConnectionCheckRequest, Identifier, SessionCredentialRef, TargetDraft
from workflow.session_credentials import SessionCredentialError, canonical_bound_origin


class LocalProbeRequest(ConnectionCheckRequest):
    pass


class DiscoveryProbeRequest(ClosedModel):
    discovery_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    profile: ManagedProfile
    authorization_confirmed: Literal[True]
    sample_input: str | None = Field(default=None, min_length=1, max_length=512)


class SetSessionCredentialRequest(ClosedModel):
    scope_kind: Literal["target", "discovery", "draft"]
    scope_id: Identifier
    endpoint: str = Field(min_length=1, max_length=256)
    auth_type: Literal["bearer", "api_key"]
    header_name: str | None = Field(default=None, min_length=1, max_length=64)
    secret_value: str = Field(min_length=1, max_length=4096)
    ref_id: SessionCredentialRef | None = None


class ClearSessionCredentialRequest(ClosedModel):
    ref_id: SessionCredentialRef | None = None
    target_id: Identifier | None = None
    scope_kind: Literal["target", "discovery", "draft"] | None = None
    scope_id: Identifier | None = None


def register_target_routes(app, ctx) -> None:
    """Register target, discovery, application-context, and evidence routes on app."""

    catalog = ctx.catalog
    managed = ctx.managed
    local_single_user = ctx.local_single_user
    dispatcher = ctx.dispatcher
    admin_lock = ctx.admin_lock
    discovery = ctx.discovery
    imported_service = ctx.imported_service
    application_contexts = ctx.application_contexts
    evidence_sources = ctx.evidence_sources
    fail = ctx.fail
    operator_authorized = ctx.operator_authorized

    def managed_auth():
        if not managed:
            return fail("target_management_disabled", 403)
        if not operator_authorized():
            return fail("operator_authentication_required", 403)
        return None

    @app.get("/api/testing/targets")
    def targets():
        rows = catalog.public_targets()
        if imported_service is not None:
            for row in rows:
                row["connection_verification"] = imported_service.connection_state(catalog._targets[row["id"]])
        aliases = sorted(catalog._config.credential_aliases.keys())
        return jsonify(
            workflow_schema_version="1.0.0",
            targets=rows,
            credential_aliases=aliases,
            credential_alias_availability={alias: catalog._available(alias) for alias in aliases},
            protocols=[
                {"id": "openai-chat", "state": "offline_configuration_supported"},
                {"id": "http-json", "state": "offline_configuration_supported"},
                {"id": "mcp-jsonrpc", "state": "local_discovery_and_review_supported"},
                {"id": "a2a", "state": "unsupported"},
            ],
        )

    @app.post("/api/testing/target-drafts/validate")
    def validate():
        try:
            draft = TargetDraft.model_validate(read_json(request.get_data()))
        except (ValueError, TypeError, ValidationError):
            return fail("invalid_draft", 400)
        errors = catalog.validate(draft)
        return jsonify(
            workflow_schema_version="1.0.0",
            configuration_status="invalid" if errors else "valid",
            errors=errors,
            target_id=draft.target_id,
            profile_revision=draft.profile_revision,
            connection_reachable=None,
            runtime_protocol_compatible=None,
            target_execution_performed=False,
            security_verdict=None,
        )

    @app.post("/api/testing/connection-checks")
    def connection_check():
        if managed and not operator_authorized():
            return fail("operator_authentication_required", 403)
        try:
            selection = (LocalProbeRequest if local_single_user else ConnectionCheckRequest).model_validate(
                read_json(request.get_data())
            )
        except (ValueError, TypeError, ValidationError):
            return fail("invalid_connection_selection", 400)
        with admin_lock, dispatcher._lock if dispatcher else nullcontext():
            if dispatcher and dispatcher._active:
                return fail("run_active", 409)
            preset = catalog._targets.get(selection.target_id)
            # Generic HTTP JSON POST probes can trigger target actions, so require
            # explicit per-probe authorization and exact endpoint binding even for
            # already-reviewed profiles (both local_single_user and authenticated modes).
            if preset is not None and preset.protocol == "http-json":
                if (
                    selection.profile_revision != catalog._revisions[preset.id]
                    or selection.policy_ref != catalog._config.policy_ref
                ):
                    return fail("stale_profile_or_policy", 409)
                if selection.authorization_confirmed is not True or selection.endpoint != preset.endpoint:
                    return fail("probe_authorization_required", 403)
            if local_single_user:
                if preset is not None and not preset.reviewed:
                    if (
                        selection.authorization_confirmed is not True
                        or selection.endpoint != preset.endpoint
                        or selection.profile_revision != catalog._revisions[preset.id]
                        or selection.policy_ref != catalog._config.policy_ref
                    ):
                        return fail("probe_authorization_required", 403)
                    try:
                        catalog.review_profile(
                            ReviewProfile(
                                target_id=preset.id,
                                profile_revision=selection.profile_revision,
                                policy_ref=selection.policy_ref,
                                endpoint=preset.endpoint,
                                protocol=preset.protocol,
                                model=preset.default_model,
                                capabilities=(
                                    ["tool_call"]
                                    if preset.protocol == "mcp-jsonrpc"
                                    else (["http_json"] if preset.protocol == "http-json" else ["chat"])
                                ),
                                authorization_confirmed=True,
                            )
                        )
                    except (ValueError, OSError, ValidationError):
                        return fail("probe_authorization_rejected", 409)
            result, status = catalog.connection_check(selection)
            if imported_service is not None:
                preset = catalog._targets.get(selection.target_id)
                if preset is not None:
                    imported_service.record_connection_check(preset, result)
        return jsonify(result.model_dump()), status

    @app.get("/api/testing/evidence-sources/target/<target_id>")
    def evidence_list(target_id):
        denied = managed_auth()
        if denied:
            return denied
        try:
            return jsonify(
                workflow_schema_version="1.0.0",
                sources=evidence_sources.list(target_id),
                allowed_endpoints=[p.model_dump() for p in evidence_sources.policy.allowed_endpoints],
                source_types=["http_json"],
                collection_modes=["snapshot"],
                action_verification_supported=False,
            )
        except (ValueError, OSError):
            return fail("evidence_storage_unavailable", 409)

    @app.post("/api/testing/evidence-sources/save")
    def evidence_save():
        denied = managed_auth()
        if denied:
            return denied
        try:
            selection = SaveEvidenceSource.model_validate(read_json(request.get_data()))
            with admin_lock:
                source = evidence_sources.save(selection.profile, selection.source_id, selection.expected_revision)
            return jsonify(workflow_schema_version="1.0.0", source=source)
        except EvidenceSourceError as exc:
            return fail(str(exc), 409)
        except (ValueError, OSError):
            return fail("invalid_evidence_source", 400)

    @app.post("/api/testing/evidence-sources/collect")
    def evidence_collect():
        denied = managed_auth()
        if denied:
            return denied
        try:
            selection = CollectEvidenceSource.model_validate(read_json(request.get_data()))
            with admin_lock, (dispatcher._lock if dispatcher else nullcontext()):
                if dispatcher and dispatcher._active:
                    return fail("active_run_blocks_source_collection", 409)
                capture = evidence_sources.collect(
                    selection.source_id, selection.expected_revision, selection.authorization_confirmed
                )
            return jsonify(workflow_schema_version="1.0.0", capture=capture)
        except EvidenceSourceError as exc:
            return fail(str(exc), 409)
        except (ValueError, OSError):
            return fail("invalid_evidence_collection", 400)

    @app.get("/api/testing/evidence-captures/<capture_id>")
    def evidence_capture(capture_id):
        denied = managed_auth()
        if denied:
            return denied
        try:
            return jsonify(workflow_schema_version="1.0.0", capture=evidence_sources.capture(capture_id))
        except (ValueError, OSError):
            return fail("evidence_capture_unavailable", 409)

    @app.get("/api/testing/managed-targets")
    def managed_targets():
        denied = managed_auth()
        if denied:
            return denied
        rows = catalog.public_targets()
        if imported_service is not None:
            for row in rows:
                row["connection_verification"] = imported_service.connection_state(catalog._targets[row["id"]])
        aliases = sorted(catalog._config.credential_aliases.keys())
        return jsonify(
            workflow_schema_version="1.0.0",
            targets=rows,
            policy_ref=catalog._config.policy_ref,
            credential_aliases=aliases,
            credential_alias_availability={alias: catalog._available(alias) for alias in aliases},
        )

    def _collect_target_artifacts(target_id: str) -> tuple[list[tuple[str, Path]], dict[str, int]]:
        """Identify all target-scoped files and directories across managed stores."""
        data_dir = Path(catalog.data_dir)
        targets_to_purge: list[tuple[str, Path]] = []
        counts = {
            "application_contexts": 0,
            "discoveries": 0,
            "evidence_sources": 0,
            "policies_and_contracts": 0,
            "scan_runs": 0,
        }

        # 1. ApplicationContext
        app_ctx_file = data_dir / "application-contexts" / f"{target_id}.json"
        if app_ctx_file.is_file():
            targets_to_purge.append(("file", app_ctx_file))
            counts["application_contexts"] += 1

        # 2. Discoveries associated with target_id
        disc_dir = data_dir / "discoveries"
        if disc_dir.is_dir():
            for p in sorted(disc_dir.glob("*.json")):
                if p.name.endswith(".mcp-tools.json"):
                    continue
                try:
                    doc = json.loads(p.read_text(encoding="utf-8"))
                except Exception:
                    continue
                proposed = doc.get("proposed_profile") if isinstance(doc, dict) else None
                if isinstance(doc, dict) and (
                    doc.get("saved_target_id") == target_id
                    or (doc.get("saved_target_id") is None and isinstance(proposed, dict) and proposed.get("id") == target_id)
                ):
                    targets_to_purge.append(("file", p))
                    counts["discoveries"] += 1
                    mcp_tools = disc_dir / f"{p.stem}.mcp-tools.json"
                    if mcp_tools.is_file():
                        targets_to_purge.append(("file", mcp_tools))

        # 3. Evidence Sources & Captures
        ev_root = data_dir / "evidence-sources-v1"
        if ev_root.is_dir():
            source_ids: set[str] = set()
            prof_dir = ev_root / "profiles"
            if prof_dir.is_dir():
                for p in sorted(prof_dir.glob("*.json")):
                    try:
                        doc = json.loads(p.read_text(encoding="utf-8"))
                    except Exception:
                        continue
                    if isinstance(doc, dict) and doc.get("target_id") == target_id:
                        source_ids.add(p.stem)
                        targets_to_purge.append(("file", p))
                        counts["evidence_sources"] += 1
            if source_ids:
                rev_dir = ev_root / "revisions"
                if rev_dir.is_dir():
                    for p in sorted(rev_dir.glob("*.json")):
                        if any(p.name.startswith(f"{sid}-") for sid in source_ids):
                            targets_to_purge.append(("file", p))
                for p in sorted(ev_root.glob("*-status.json")):
                    if any(p.name.startswith(f"{sid}-") for sid in source_ids):
                        targets_to_purge.append(("file", p))
                cap_dir = ev_root / "captures"
                if cap_dir.is_dir():
                    for p in sorted(cap_dir.glob("*.json")):
                        try:
                            doc = json.loads(p.read_text(encoding="utf-8"))
                        except Exception:
                            continue
                        if isinstance(doc, dict) and (
                            doc.get("target_id") == target_id or doc.get("source_id") in source_ids
                        ):
                            targets_to_purge.append(("file", p))

        # 4. Target-specific policies, contracts, and MCP catalogs/bindings
        for subdir, field_path in (
            ("asi03-target-policies", ("draft", "target_id")),
            ("asi05-response-policies", ("draft", "target_id")),
            ("asi03-contracts", ("draft", "target_id")),
            ("mcp-tool-catalogs", ("draft", "mcp_target_id")),
            ("mcp-agent-bindings", ("draft", "llm_target_id")),
            ("mcp-agent-bindings", ("draft", "mcp_target_id")),
            ("response_policies", ("target_id",)),
        ):
            folder = data_dir / subdir
            if not folder.is_dir():
                continue
            for p in sorted(folder.glob("*.json")):
                if any(existing_p == p for _, existing_p in targets_to_purge):
                    continue
                try:
                    doc = json.loads(p.read_text(encoding="utf-8"))
                except Exception:
                    continue
                cur: Any = doc
                for k in field_path:
                    cur = cur.get(k) if isinstance(cur, dict) else None
                if cur == target_id:
                    targets_to_purge.append(("file", p))
                    counts["policies_and_contracts"] += 1

        # Also check generic_run_service.policy_store._root (whether inside or outside data_dir)
        gen_svc = getattr(ctx, "generic_run_service", None)
        pol_store = getattr(gen_svc, "policy_store", None)
        pol_root = getattr(pol_store, "_root", None)
        if isinstance(pol_root, Path) and pol_root.is_dir():
            for p in sorted(pol_root.glob("*.json")):
                if any(existing_p == p for _, existing_p in targets_to_purge):
                    continue
                try:
                    doc = json.loads(p.read_text(encoding="utf-8"))
                except Exception:
                    continue
                if isinstance(doc, dict) and (
                    doc.get("target_id") == target_id
                    or (isinstance(doc.get("draft"), dict) and doc["draft"].get("target_id") == target_id)
                ):
                    targets_to_purge.append(("file", p))
                    counts["policies_and_contracts"] += 1

        # 5. Scan history, execution results, batch runs, grants, claims, and controlled runs bound to target_id
        purged_run_ids: set[str] = set()
        purged_grant_ids: set[str] = set()

        runs_root = getattr(gen_svc, "runs_root", None)
        if isinstance(runs_root, Path) and runs_root.is_dir():
            for run_dir in sorted(runs_root.iterdir()):
                if not run_dir.is_dir():
                    continue
                rec_file = run_dir / "generic-run.json"
                if rec_file.is_file():
                    try:
                        doc = json.loads(rec_file.read_text(encoding="utf-8"))
                    except Exception:
                        continue
                    if isinstance(doc, dict) and doc.get("target_id") == target_id:
                        targets_to_purge.append(("dir", run_dir))
                        counts["scan_runs"] += 1
                        for case_row in doc.get("cases") or []:
                            if isinstance(case_row, dict) and isinstance(case_row.get("run_id"), str):
                                purged_run_ids.add(case_row["run_id"])

        ctrl_roots: list[Path] = []
        for candidate_root in (
            getattr(gen_svc, "controlled_runs_root", None),
            getattr(dispatcher, "output_root", None),
            getattr(getattr(ctx, "mcp_action_service", None), "output_root", None),
        ):
            if isinstance(candidate_root, Path) and candidate_root not in ctrl_roots:
                ctrl_roots.append(candidate_root)

        for c_root in ctrl_roots:
            if not c_root.is_dir():
                continue
            batch_root = c_root / "batch-runs"
            if batch_root.is_dir():
                for b_entry in sorted(batch_root.iterdir()):
                    if any(existing_p == b_entry for _, existing_p in targets_to_purge):
                        continue
                    if b_entry.is_dir():
                        state_file = b_entry / "state.json"
                        if state_file.is_file():
                            try:
                                b_doc = json.loads(state_file.read_text(encoding="utf-8"))
                            except Exception:
                                continue
                            snap = b_doc.get("snapshot") if isinstance(b_doc, dict) else None
                            prov = snap.get("imported_provenance") if isinstance(snap, dict) else None
                            if isinstance(snap, dict) and (
                                snap.get("target_id") == target_id
                                or (isinstance(prov, dict) and prov.get("mcp_target_id") == target_id)
                            ):
                                targets_to_purge.append(("dir", b_entry))
                                counts["scan_runs"] += 1
                                for r_row in b_doc.get("results") or []:
                                    if isinstance(r_row, dict) and isinstance(r_row.get("report_run_id"), str):
                                        purged_run_ids.add(r_row["report_run_id"])
                    elif b_entry.is_file():
                        try:
                            b_doc = json.loads(b_entry.read_text(encoding="utf-8"))
                        except Exception:
                            continue
                        if isinstance(b_doc, dict) and (
                            b_doc.get("target_id") == target_id
                            or b_doc.get("mcp_target_id") == target_id
                            or (isinstance(b_doc.get("target"), dict) and b_doc["target"].get("target_id") == target_id)
                        ):
                            targets_to_purge.append(("file", b_entry))
                            counts["scan_runs"] += 1
                            if isinstance(b_doc.get("grant_id"), str):
                                purged_grant_ids.add(b_doc["grant_id"])

            for entry in sorted(c_root.iterdir()):
                if entry.name == "batch-runs" or any(existing_p == entry for _, existing_p in targets_to_purge):
                    continue
                if entry.is_dir():
                    sum_file = entry / "run-summary.json"
                    if sum_file.is_file():
                        try:
                            doc = json.loads(sum_file.read_text(encoding="utf-8"))
                        except Exception:
                            continue
                        if isinstance(doc, dict) and (
                            doc.get("target_id") == target_id or entry.name in purged_run_ids
                        ):
                            targets_to_purge.append(("dir", entry))
                            counts["scan_runs"] += 1
                            purged_run_ids.add(entry.name)
                            if isinstance(doc.get("run_id"), str):
                                purged_run_ids.add(doc["run_id"])
                elif entry.is_file() and entry.suffix == ".json":
                    try:
                        doc = json.loads(entry.read_text(encoding="utf-8"))
                    except Exception:
                        continue
                    if isinstance(doc, dict) and (
                        doc.get("target_id") == target_id
                        or (isinstance(doc.get("target"), dict) and doc["target"].get("target_id") == target_id)
                    ):
                        targets_to_purge.append(("file", entry))
                        counts["scan_runs"] += 1
                        if isinstance(doc.get("grant_id"), str):
                            purged_grant_ids.add(doc["grant_id"])

            if purged_run_ids or purged_grant_ids:
                claim_names = {f"claim-auth-{gid}" for gid in purged_grant_ids}
                for claim_entry in sorted(c_root.glob("claim-*")):
                    if not claim_entry.is_file() or any(existing_p == claim_entry for _, existing_p in targets_to_purge):
                        continue
                    matched_claim = claim_entry.name in claim_names
                    if not matched_claim:
                        try:
                            c_doc = json.loads(claim_entry.read_text(encoding="utf-8"))
                            matched_claim = isinstance(c_doc, dict) and c_doc.get("run_id") in purged_run_ids
                        except Exception:
                            matched_claim = False
                    if matched_claim:
                        targets_to_purge.append(("file", claim_entry))

        return targets_to_purge, counts

    def _remove_artifact_entry(kind: str, path: Path) -> None:
        if kind == "file":
            if path.exists():
                path.unlink()
        elif kind == "dir":
            if path.exists():
                shutil.rmtree(path)

    @app.post("/api/testing/managed-targets/delete")
    def managed_delete_target():
        denied = managed_auth()
        if denied:
            return denied
        try:
            item = DeleteTargetRequest.model_validate(read_json(request.get_data()))
        except (ValueError, TypeError, ValidationError):
            return fail("delete_target_rejected", 409)

        gen_svc = getattr(ctx, "generic_run_service", None)
        mcp_act_svc = getattr(ctx, "mcp_action_service", None)
        gen_lock = getattr(gen_svc, "_lock", None)
        with (
            admin_lock,
            dispatcher._lock if dispatcher else nullcontext(),
            catalog._lock,
            gen_lock if gen_lock is not None else nullcontext(),
        ):
            if dispatcher and dispatcher._active:
                return fail("run_active", 409)
            if gen_svc is not None and gen_svc.is_active_for_target(item.target_id):
                return fail("run_active", 409)
            if mcp_act_svc is not None and getattr(mcp_act_svc, "_lock", None) is not None and mcp_act_svc._lock.locked():
                return fail("run_active", 409)
            for svc in (ctx.services or {}).values():
                active_batch = getattr(svc, "_active", None)
                if isinstance(active_batch, dict) and active_batch.get("target_id") == item.target_id:
                    return fail("run_active", 409)
                if getattr(svc, "active_target_id", None) == item.target_id:
                    return fail("run_active", 409)
                orch = getattr(svc, "orchestrator", None)
                if getattr(orch, "_active", False):
                    return fail("run_active", 409)

            if (
                item.target_id not in catalog._targets
                or catalog._revisions.get(item.target_id) != item.profile_revision
            ):
                return fail("delete_target_rejected", 409)

            prev_state = catalog._state
            prev_state_bytes = catalog.state_file.read_bytes() if catalog.state_file.exists() else None
            legacy_backup_path = getattr(catalog, "legacy_backup_file", None)
            prev_legacy_backup_bytes = (
                legacy_backup_path.read_bytes()
                if isinstance(legacy_backup_path, Path) and legacy_backup_path.exists()
                else None
            )
            prev_conn_proof = (
                imported_service._connection_proofs.get(item.target_id)
                if imported_service is not None and hasattr(imported_service, "_connection_proofs")
                else None
            )
            prev_conn_legacy = (
                imported_service._connections.get(item.target_id)
                if imported_service is not None and hasattr(imported_service, "_connections")
                else None
            )
            prev_dispatcher_policy = getattr(dispatcher, "policy", None) if dispatcher is not None else None
            artifacts, purged_counts = _collect_target_artifacts(item.target_id)

            # Snapshot every file to be deleted in memory for best-effort in-process exception rollback
            file_backups: list[tuple[Path, bytes]] = []
            for kind, path in artifacts:
                if kind == "file" and path.is_file():
                    file_backups.append((path, path.read_bytes()))
                elif kind == "dir" and path.is_dir():
                    for sub in sorted(path.rglob("*")):
                        if sub.is_file():
                            file_backups.append((sub, sub.read_bytes()))

            try:
                active_targets = catalog.delete_target(item)
                for kind, path in artifacts:
                    _remove_artifact_entry(kind, path)
                if imported_service is not None:
                    if hasattr(imported_service, "_connection_proofs"):
                        imported_service._connection_proofs.pop(item.target_id, None)
                    if hasattr(imported_service, "_connections"):
                        imported_service._connections.pop(item.target_id, None)
                if hasattr(catalog, "session_credentials") and catalog.session_credentials is not None:
                    catalog.session_credentials.clear_for_scope("target", item.target_id)
                if dispatcher is not None and getattr(dispatcher, "policy", None) is not None:
                    surviving_grants = [
                        g for g in dispatcher.policy.grants if getattr(g, "target_id", None) != item.target_id
                    ]
                    if len(surviving_grants) != len(dispatcher.policy.grants):
                        dispatcher.policy = dispatcher.policy.model_copy(update={"grants": surviving_grants})
            except Exception as exc:
                # Best-effort in-process rollback: restore catalog state, legacy backup, in-memory state, and backed-up artifacts
                if prev_state_bytes is not None:
                    catalog.state_file.write_bytes(prev_state_bytes)
                elif catalog.state_file.exists():
                    catalog.state_file.unlink()
                if isinstance(legacy_backup_path, Path):
                    if prev_legacy_backup_bytes is not None:
                        legacy_backup_path.write_bytes(prev_legacy_backup_bytes)
                    elif legacy_backup_path.exists():
                        legacy_backup_path.unlink()
                catalog._install(prev_state)
                if imported_service is not None:
                    if prev_conn_proof is not None and hasattr(imported_service, "_connection_proofs"):
                        imported_service._connection_proofs[item.target_id] = prev_conn_proof
                    if prev_conn_legacy is not None and hasattr(imported_service, "_connections"):
                        imported_service._connections[item.target_id] = prev_conn_legacy
                if dispatcher is not None and prev_dispatcher_policy is not None:
                    dispatcher.policy = prev_dispatcher_policy
                for path, raw_bytes in file_backups:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(raw_bytes)
                err_code = "legacy_backup_corrupted" if isinstance(exc, CatalogError) and str(exc) == "legacy_backup_corrupted" else "delete_target_rejected"
                return fail(err_code, 409)

        return jsonify(
            workflow_schema_version="1.0.0",
            deleted_target_id=item.target_id,
            purged_counts=purged_counts,
            active_targets=active_targets,
        )

    @app.get("/api/testing/application-contexts/target/<target_id>")
    def read_application_context(target_id):
        denied = managed_auth()
        if denied:
            return denied
        try:
            with admin_lock:
                row = application_contexts.read(target_id)
                current = catalog._revisions.get(target_id)
            return jsonify(
                workflow_schema_version="1.0.0",
                context=row,
                binding_status="current" if row is None or row["draft"]["target_revision"] == current else "stale",
            )
        except (ValueError, OSError, ValidationError, TypeError, KeyError):
            return fail("application_context_unavailable", 409)

    @app.post("/api/testing/application-contexts/save")
    def save_application_context():
        denied = managed_auth()
        if denied:
            return denied
        try:
            item = SaveApplicationContext.model_validate(read_json(request.get_data()))
            with admin_lock:
                row = application_contexts.save(item)
            return jsonify(workflow_schema_version="1.0.0", context=row, binding_status="current")
        except (ValueError, OSError, ValidationError, TypeError, KeyError):
            return fail("application_context_rejected", 409)

    @app.post("/api/testing/discoveries")
    def discover_target():
        denied = managed_auth()
        if denied:
            return denied
        try:
            item = DiscoveryRequest.model_validate(read_json(request.get_data()))
            with admin_lock, dispatcher._lock if dispatcher else nullcontext():
                if dispatcher and dispatcher._active:
                    return fail("run_active", 409)
                result = discovery.discover(
                    item,
                    allowed_aliases=set(catalog._config.credential_aliases),
                    testcase_items=[],
                    text_case_ids=set(),
                )
            return jsonify(result)
        except (ValueError, TypeError, ValidationError) as exc:
            if isinstance(exc, DiscoveryError):
                return fail(
                    exc.code,
                    {
                        "invalid_discovery_url": 400,
                        "unknown_credential_alias": 400,
                        "unsafe_discovery_destination": 403,
                        "discovery_response_too_large": 413,
                    }.get(exc.code, 409),
                )
            return fail("invalid_discovery_request", 400)
        except OSError:
            return fail("discovery_storage_unavailable", 500)

    @app.get("/api/testing/discoveries/<discovery_id>")
    def read_discovery(discovery_id):
        denied = managed_auth()
        if denied:
            return denied
        try:
            return jsonify(discovery.load(discovery_id))
        except DiscoveryError as exc:
            return fail(exc.code, 404)

    @app.get("/api/testing/discoveries/<discovery_id>/mcp-tools")
    def read_discovery_mcp_tools(discovery_id):
        denied = managed_auth()
        if denied:
            return denied
        try:
            return jsonify(discovery.load_mcp_capabilities(discovery_id))
        except DiscoveryError as exc:
            return fail(exc.code, 404)

    def _has_active_run(target_id: str | None = None) -> bool:
        gen_svc = getattr(ctx, "generic_run_service", None)
        mcp_act_svc = getattr(ctx, "mcp_action_service", None)
        if dispatcher and dispatcher._active:
            return True
        if gen_svc is not None:
            if target_id is not None and gen_svc.is_active_for_target(target_id):
                return True
            if target_id is None and bool(getattr(gen_svc, "_active_target_counts", None)):
                return True
        if mcp_act_svc is not None and getattr(mcp_act_svc, "_lock", None) is not None and mcp_act_svc._lock.locked():
            return True
        for svc in (ctx.services or {}).values():
            active_batch = getattr(svc, "_active", None)
            if isinstance(active_batch, dict) and (target_id is None or active_batch.get("target_id") == target_id):
                return True
            active_tid = getattr(svc, "active_target_id", None)
            if active_tid is not None and (target_id is None or active_tid == target_id):
                return True
            orch = getattr(svc, "orchestrator", None)
            if getattr(orch, "_active", False):
                return True
        return False

    @app.post("/api/testing/managed-targets/session-credentials")
    def managed_set_session_credential():
        denied = managed_auth()
        if denied:
            return denied
        try:
            item = SetSessionCredentialRequest.model_validate(read_json(request.get_data()))
        except (ValueError, TypeError, ValidationError):
            return fail("invalid_session_credential", 400)
        gen_svc = getattr(ctx, "generic_run_service", None)
        gen_lock = getattr(gen_svc, "_lock", None)
        with (
            admin_lock,
            dispatcher._lock if dispatcher else nullcontext(),
            catalog._lock,
            gen_lock if gen_lock is not None else nullcontext(),
        ):
            if _has_active_run(item.scope_id if item.scope_kind == "target" else None):
                return fail("run_active", 409)
            try:
                if item.scope_kind == "target":
                    preset = catalog._targets.get(item.scope_id)
                    if preset is None or preset.protocol != "http-json":
                        return fail("invalid_session_credential", 400)
                    if canonical_bound_origin(item.endpoint) != canonical_bound_origin(preset.endpoint):
                        return fail("session_credential_origin_mismatch", 400)
                    expected_hdr = item.header_name or ("Authorization" if item.auth_type == "bearer" else "X-API-Key")
                    if preset.session_auth is not None:
                        if (
                            item.auth_type != preset.session_auth.auth_type
                            or expected_hdr.lower() != preset.session_auth.header_name.lower()
                        ):
                            return fail("session_credential_header_mismatch", 400)
                        if item.ref_id is not None and item.ref_id != preset.session_auth.ref_id:
                            return fail("session_credential_scope_mismatch", 400)
                        ref_to_use = preset.session_auth.ref_id
                    else:
                        ref_to_use = item.ref_id
                elif item.scope_kind == "discovery":
                    if discovery is None:
                        return fail("discovery_record_not_found", 404)
                    record = discovery.load(item.scope_id)
                    disc_endpoints = {
                        c.get("endpoint")
                        for c in (record.get("openapi_candidates") or [])
                        if isinstance(c, dict) and isinstance(c.get("endpoint"), str)
                    }
                    if isinstance(record.get("canonical_endpoint"), str):
                        disc_endpoints.add(record["canonical_endpoint"])
                    if disc_endpoints and canonical_bound_origin(item.endpoint) not in {
                        canonical_bound_origin(ep) for ep in disc_endpoints if ep
                    }:
                        return fail("session_credential_origin_mismatch", 400)
                    ref_to_use = item.ref_id
                else:
                    if item.ref_id is not None and any(
                        p.session_auth is not None and p.session_auth.ref_id == item.ref_id
                        for p in catalog._targets.values()
                    ):
                        return fail("session_credential_scope_mismatch", 400)
                    ref_to_use = item.ref_id
                meta = catalog.session_credentials.set_credential(
                    scope_kind=item.scope_kind,
                    scope_id=item.scope_id,
                    endpoint=item.endpoint,
                    auth_type=item.auth_type,
                    header_name=item.header_name,
                    secret_value=item.secret_value,
                    ref_id=ref_to_use,
                )
            except DiscoveryError as exc:
                return fail(exc.code, 404)
            except SessionCredentialError as exc:
                status = 409 if exc.code == "session_credential_capacity_exceeded" else 400
                return fail(exc.code, status)
        return jsonify(workflow_schema_version="1.0.0", credential=meta)

    @app.post("/api/testing/managed-targets/session-credentials/clear")
    def managed_clear_session_credential():
        denied = managed_auth()
        if denied:
            return denied
        try:
            item = ClearSessionCredentialRequest.model_validate(read_json(request.get_data()))
        except (ValueError, TypeError, ValidationError):
            return fail("invalid_session_credential", 400)
        if not item.ref_id and not item.target_id and not (item.scope_kind and item.scope_id):
            return fail("invalid_session_credential", 400)
        gen_svc = getattr(ctx, "generic_run_service", None)
        gen_lock = getattr(gen_svc, "_lock", None)
        with (
            admin_lock,
            dispatcher._lock if dispatcher else nullcontext(),
            catalog._lock,
            gen_lock if gen_lock is not None else nullcontext(),
        ):
            if _has_active_run(item.target_id):
                return fail("run_active", 409)
            cleared = False
            try:
                if item.ref_id:
                    cleared = catalog.session_credentials.clear_credential(
                        item.ref_id,
                        scope_id=item.target_id or item.scope_id,
                        scope_kind="target" if item.target_id else item.scope_kind,
                    )
                if item.target_id:
                    cleared = (catalog.session_credentials.clear_for_scope("target", item.target_id) > 0) or cleared
                elif item.scope_kind and item.scope_id:
                    cleared = (catalog.session_credentials.clear_for_scope(item.scope_kind, item.scope_id) > 0) or cleared
            except SessionCredentialError as exc:
                return fail(exc.code, 400)
        return jsonify(
            workflow_schema_version="1.0.0",
            cleared=cleared,
            credential_availability="unavailable",
        )

    @app.post("/api/testing/discovery-probes")
    def probe_discovery_candidate():
        denied = managed_auth()
        if denied:
            return denied
        try:
            item = DiscoveryProbeRequest.model_validate(read_json(request.get_data()))
            with admin_lock, dispatcher._lock if dispatcher else nullcontext():
                if dispatcher and dispatcher._active:
                    return fail("run_active", 409)
                discovery.validate_association(
                    item.discovery_id,
                    item.profile.endpoint,
                    item.profile.protocol,
                    credential_alias=item.profile.credential_alias,
                    session_auth=item.profile.session_auth,
                )
                result, status = catalog.probe_candidate(
                    item.profile,
                    sample_input=item.sample_input,
                    discovery_id=item.discovery_id,
                )
            return jsonify(result.model_dump()), status
        except DiscoveryError as exc:
            status_code = 400 if exc.code in {"discovery_authentication_required", "unsupported_authentication_scheme"} else 409
            return fail(exc.code, status_code)
        except (ValueError, TypeError, ValidationError):
            return fail("invalid_discovery_probe", 400)

    @app.post("/api/testing/managed-targets/validate")
    def managed_validate():
        denied = managed_auth()
        if denied:
            return denied
        try:
            item = SaveProfile.model_validate(read_json(request.get_data()))
            update = item.expected_profile_revision is not None
            if update and catalog._revisions.get(item.profile.id) != item.expected_profile_revision:
                return fail("stale_profile_revision", 409)
            if item.discovery_id:
                discovery.validate_association(
                    item.discovery_id,
                    item.profile.endpoint,
                    item.profile.protocol,
                    credential_alias=item.profile.credential_alias,
                    session_auth=item.profile.session_auth,
                )
            candidate = catalog.validate_profile(item.profile, update=update)
            if candidate.session_auth is not None:
                if update:
                    allowed_checks = [("target", candidate.id), ("draft", candidate.id)]
                elif item.discovery_id:
                    allowed_checks = [("discovery", item.discovery_id), ("draft", candidate.id)]
                else:
                    allowed_checks = [("draft", candidate.id)]
                avail = "unavailable"
                for skind, sid in allowed_checks:
                    if catalog.session_credentials.availability(
                        candidate.session_auth.ref_id,
                        endpoint=candidate.endpoint,
                        scope_id=sid,
                        scope_kind=skind,
                        expected_auth_type=candidate.session_auth.auth_type,
                        expected_header_name=candidate.session_auth.header_name,
                    ) == "available":
                        avail = "available"
                        break
            else:
                avail = catalog._available(candidate.credential_alias)
        except DiscoveryError as exc:
            status_code = 400 if exc.code in {"discovery_authentication_required", "unsupported_authentication_scheme"} else 409
            return fail(exc.code, status_code)
        except (ValueError, TypeError, ValidationError):
            return fail("invalid_managed_profile", 400)
        return jsonify(
            workflow_schema_version="1.0.0",
            configuration_status="valid",
            credential_availability=avail,
            target_request_count=0,
            target_execution_performed=False,
        )

    def managed_write(update=False, review=False):
        denied = managed_auth()
        if denied:
            return denied
        try:
            item = (ReviewProfile if review else SaveProfile).model_validate(read_json(request.get_data()))
        except (ValueError, TypeError, ValidationError):
            return fail("invalid_managed_profile", 400)
        gen_svc = getattr(ctx, "generic_run_service", None)
        gen_lock = getattr(gen_svc, "_lock", None)
        target_id = item.target_id if review else item.profile.id
        try:
            with (
                admin_lock,
                dispatcher._lock if dispatcher else nullcontext(),
                catalog._lock,
                gen_lock if gen_lock is not None else nullcontext(),
            ):
                if _has_active_run(target_id if (update or review) else None):
                    return fail("run_active", 409)
                if not review and item.discovery_id:
                    discovery.validate_association(
                        item.discovery_id,
                        item.profile.endpoint,
                        item.profile.protocol,
                        credential_alias=item.profile.credential_alias,
                        session_auth=item.profile.session_auth,
                    )
                allowed_scopes: set[tuple[str, str]] = set()
                if not review and item.profile.session_auth is not None:
                    if update:
                        allowed_scopes = {("target", item.profile.id), ("draft", item.profile.id)}
                    elif item.discovery_id:
                        allowed_scopes = {("discovery", item.discovery_id), ("draft", item.profile.id)}
                    else:
                        allowed_scopes = {("draft", item.profile.id)}
                    # Read-only pre-validation BEFORE catalog.save_profile so a failed save
                    # NEVER mutates or commits session credential ownership.
                    catalog.session_credentials.validate_rebind_to_target(
                        item.profile.session_auth.ref_id,
                        endpoint=item.profile.endpoint,
                        expected_auth_type=item.profile.session_auth.auth_type,
                        expected_header_name=item.profile.session_auth.header_name,
                        allowed_scopes=allowed_scopes,
                    )
                prev_preset = catalog._targets.get(item.profile.id) if (not review and update) else None
                prev_session_ref = (
                    prev_preset.session_auth.ref_id
                    if (prev_preset is not None and prev_preset.session_auth is not None)
                    else None
                )
                prev_state = catalog._state if not review else None
                prev_state_bytes = (
                    catalog.state_file.read_bytes()
                    if (not review and catalog.state_file.exists())
                    else None
                )
                new_ref_id = (
                    item.profile.session_auth.ref_id
                    if (not review and item.profile.session_auth is not None)
                    else None
                )
                new_ref_snapshot = (
                    catalog.session_credentials.snapshot_record(new_ref_id)
                    if new_ref_id is not None
                    else None
                )
                prev_ref_snapshot = (
                    catalog.session_credentials.snapshot_record(prev_session_ref)
                    if prev_session_ref is not None
                    else None
                )

                profile = (
                    catalog.review_profile(item) if review else catalog.save_profile(item, update=update)
                )
                try:
                    if not review and item.profile.session_auth is not None:
                        catalog.session_credentials.rebind_to_target(
                            item.profile.session_auth.ref_id,
                            target_id=item.profile.id,
                            endpoint=item.profile.endpoint,
                            expected_auth_type=item.profile.session_auth.auth_type,
                            expected_header_name=item.profile.session_auth.header_name,
                            allowed_scopes=allowed_scopes,
                        )
                    if not review and item.discovery_id:
                        discovery.associate(item.discovery_id, profile)
                    if (
                        not review
                        and update
                        and prev_session_ref is not None
                        and (item.profile.session_auth is None or item.profile.session_auth.ref_id != prev_session_ref)
                    ):
                        catalog.session_credentials.clear_credential(
                            prev_session_ref, scope_id=item.profile.id, scope_kind="target"
                        )
                    if not review:
                        # Release any other leftover draft credentials for this target ID now that save succeeded.
                        catalog.session_credentials.clear_for_scope("draft", item.profile.id)
                        profile = next(r for r in catalog.public_targets() if r["id"] == item.profile.id)
                except Exception:
                    # Roll back in-memory credential ownership and persisted catalog on post-save failure.
                    if new_ref_id is not None:
                        catalog.session_credentials.restore_record(new_ref_id, new_ref_snapshot)
                    if prev_session_ref is not None:
                        catalog.session_credentials.restore_record(prev_session_ref, prev_ref_snapshot)
                    if prev_state is not None:
                        if prev_state_bytes is not None:
                            catalog.state_file.write_bytes(prev_state_bytes)
                        elif catalog.state_file.exists():
                            catalog.state_file.unlink()
                        catalog._install(prev_state)
                    raise
        except DiscoveryError as exc:
            status_code = 400 if exc.code in {"discovery_authentication_required", "unsupported_authentication_scheme"} else 409
            return fail(exc.code, status_code)
        except SessionCredentialError as exc:
            return fail(exc.code, 400)
        except ValueError as exc:
            if str(exc) == "Unregistered credential alias.":
                return fail("invalid_managed_profile", 400)
            return fail("profile_change_rejected", 409)
        except (OSError, ValidationError):
            return fail("profile_change_rejected", 409)
        return jsonify(workflow_schema_version="1.0.0", profile=profile)

    @app.post("/api/testing/managed-targets/create")
    def managed_create():
        return managed_write()

    @app.post("/api/testing/managed-targets/update")
    def managed_update():
        return managed_write(update=True)

    @app.post("/api/testing/managed-targets/review")
    def managed_review():
        return managed_write(review=True)
