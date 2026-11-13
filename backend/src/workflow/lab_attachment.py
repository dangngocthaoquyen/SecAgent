"""Offline, operator-owned preparation for the isolated ASI01 Compose lab.

No Docker command, target request or network probe is performed here. Static
Compose validation and saved attempt state cannot authorize live dispatch.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
from uuid import uuid4

import yaml
from pydantic import Field

from testing.web_fixture import WebFixture
from workflow.admission import AdmissionRequest, AdmissionService
from workflow.catalog import read_json
from workflow.models import ClosedModel
from workflow.plans import ROOT, safe_file


PROJECT = "secagent-asi01-lab"
TARGET_ID = "dvaa-researchbot-lab"
TARGET_ENDPOINT = "http://127.0.0.1:17015/v1/chat/completions"
FIXTURE_ORIGIN = "http://172.30.77.3:8787"
EXPECTED_PEER = "172.30.77.2"


class LabPreparationError(ValueError):
    """Preparation rejected without exposing a local path or secret."""


class LabAttemptReference(ClosedModel):
    attempt_id: str = Field(pattern=r"^[a-f0-9]{32}$")


@dataclass(frozen=True)
class ReviewedImages:
    dvaa_image: str
    python_image: str
    proxy_image: str

    def __post_init__(self):
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", self.dvaa_image):
            raise LabPreparationError("Reviewed DVAA image ID is required.")
        for value in (self.python_image, self.proxy_image):
            if not re.fullmatch(r"[A-Za-z0-9_./:-]+@sha256:[a-f0-9]{64}", value):
                raise LabPreparationError("Reviewed Python and proxy image digests are required.")


def static_topology_errors(root=ROOT):
    """Check the reviewed source topology; never claim it describes running Docker."""
    root = Path(root).resolve()
    compose = root / "deploy/asi01-lab/compose.yaml"
    nginx = root / "deploy/asi01-lab/nginx.conf"
    try:
        safe_file(compose, root)
        safe_file(nginx, root)
        value = yaml.safe_load(compose.read_text(encoding="utf-8"))
        proxy = nginx.read_text(encoding="utf-8")
        services = value["services"]
        networks = value["networks"]
        dvaa, fixture, gateway = (services[name] for name in ("dvaa", "fixture", "proxy"))
        if (not isinstance(services, dict) or not isinstance(networks, dict)
                or any(not isinstance(row, dict) for row in (dvaa, fixture, gateway,
                    networks["lab"], networks["access"]))):
            return ["lab_source_unavailable_or_invalid"]
    except (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError, yaml.YAMLError):
        return ["lab_source_unavailable_or_invalid"]
    errors = []
    if set(services) != {"dvaa", "fixture", "proxy"} or set(networks) != {"lab", "access"}:
        errors.append("unexpected_lab_services_or_networks")
    allowed = {
        "dvaa": {"image", "pull_policy", "environment", "networks", "restart", "security_opt", "cap_drop"},
        "fixture": {"image", "build", "user", "read_only", "environment", "working_dir",
                    "entrypoint", "command", "volumes", "tmpfs", "networks", "restart",
                    "security_opt", "cap_drop"},
        "proxy": {"image", "entrypoint", "command", "user", "read_only", "volumes",
                  "tmpfs", "ports", "networks", "sysctls", "depends_on", "restart",
                  "security_opt", "cap_drop"},
    }
    if any(set(services[name]) - fields for name, fields in allowed.items()):
        errors.append("unexpected_lab_service_settings")
    private = networks["lab"]
    if (private.get("internal") is not True or private.get("name") != "secagent-asi01-lab-private"
            or private.get("driver_opts", {}).get("com.docker.network.bridge.gateway_mode_ipv4") != "isolated"
            or private.get("ipam", {}).get("config") != [{"subnet": "172.30.77.0/24"}]):
        errors.append("private_network_mismatch")
    if (networks["access"].get("name") != "secagent-asi01-lab-access"
            or networks["access"].get("ipam", {}).get("config") != [{"subnet": "172.30.78.0/24"}]
            or networks["access"].get("internal") is True):
        errors.append("access_network_mismatch")
    if (dvaa.get("networks") != {"lab": {"ipv4_address": EXPECTED_PEER}}
            or dvaa.get("ports") or dvaa.get("volumes")
            or dvaa.get("pull_policy") != "never"
            or dvaa.get("image") != "${DVAA_IMAGE:-dvaa-deepseek:local}"
            or dvaa.get("environment", {}).get("DVAA_ALLOW_INTERNAL_FETCH") != "1"
            or dvaa.get("environment", {}).get("DVAA_RESEARCH_CACHE") != "off"):
        errors.append("dvaa_service_mismatch")
    mounts = fixture.get("volumes", [])
    if not isinstance(mounts, list) or any(not isinstance(row, dict) for row in mounts):
        return errors + ["fixture_mount_or_route_mismatch"]
    state_mounts = [row for row in mounts if isinstance(row, dict) and row.get("target") == "/state"]
    expected_readonly_mounts = {
        ("../../backend/src", "/workspace/backend/src"),
        ("../../backend/scripts/serve_asi01_web_fixture.py", "/workspace/backend/scripts/serve_asi01_web_fixture.py"),
        ("../../fixtures/asi01_web", "/workspace/fixtures/asi01_web"),
    }
    if (fixture.get("networks") != {"lab": {"ipv4_address": "172.30.77.3"}}
            or fixture.get("image") != "secagent-asi01-fixture:lab"
            or fixture.get("build") != {"context": ".", "dockerfile": "Dockerfile.fixture",
                "args": {"PYTHON_IMAGE": "${FIXTURE_PYTHON_IMAGE:?Provide a reviewed Python image digest}"}}
            or fixture.get("ports") or fixture.get("command") != ["serve", "--state-dir", "/state", "--bind", "172.30.77.3"]
            or fixture.get("entrypoint") != ["python", "/workspace/backend/scripts/serve_asi01_web_fixture.py"]
            or len(state_mounts) != 1 or state_mounts[0].get("type") != "bind"
            or not str(state_mounts[0].get("source", "")).startswith("${FIXTURE_STATE_DIR:?")
            or state_mounts[0].get("bind", {}).get("create_host_path") is not False
            or {(row.get("source"), row.get("target")) for row in mounts if row is not state_mounts[0]} != expected_readonly_mounts
            or any(row.get("read_only") is not True for row in mounts if row is not state_mounts[0])):
        errors.append("fixture_mount_or_route_mismatch")
    ports = gateway.get("ports", [])
    if (gateway.get("networks") != {"lab": {"ipv4_address": "172.30.77.4"},
                                    "access": {"ipv4_address": "172.30.78.2", "gw_priority": 1}}
            or gateway.get("image") != "${PROXY_IMAGE:?Provide a reviewed Nginx image digest}"
            or ports != [{"target": 8080, "published": "17015", "host_ip": "127.0.0.1", "protocol": "tcp"}]
            or gateway.get("volumes") != [{"type": "bind", "source": "./nginx.conf",
                "target": "/etc/nginx/nginx.conf", "read_only": True}]):
        errors.append("proxy_publication_mismatch")
    listens = re.findall(r"(?m)^\s*listen\s+([^;]+);", proxy)
    passes = re.findall(r"(?m)^\s*proxy_pass\s+([^;]+);", proxy)
    if (listens != ["172.30.78.2:8080"] or sorted(passes) != sorted([
            "http://researchbot/health", "http://researchbot/v1/chat/completions"])
            or "location / { return 404; }" not in proxy
            or "server 172.30.77.2:7015;" not in proxy
            or "location = /collector" in proxy):
        errors.append("proxy_route_mismatch")
    return errors


@dataclass(frozen=True)
class RuntimeInspection:
    """Trusted-provider result in production; tests may construct mock values."""

    fixture_mount_source: Path
    fixture_mount_target: str
    fixture_mount_type: str
    fixture_mount_readonly: bool
    dvaa_image_id: str
    dvaa_mount_count: int
    dvaa_port_publications: int
    fixture_port_publications: int
    dvaa_private_ip: str
    fixture_private_ip: str
    proxy_host_bind: str
    container_visible_url: str
    observed_collector_peer: str | None
    fixture_reachable: bool | None
    isolated_network: bool
    cleanup_scope_verified: bool


def runtime_inspection_errors(inspection: RuntimeInspection, fixture_dir: Path, page_url: str,
                              expected_dvaa_image: str):
    """Compare a provider observation; a caller-provided JSON is never accepted."""
    errors = []
    if (inspection.fixture_mount_source.resolve() != fixture_dir.resolve()
            or inspection.fixture_mount_target != "/state"
            or inspection.fixture_mount_type != "bind" or inspection.fixture_mount_readonly):
        errors.append("fixture_mount_mismatch")
    if (inspection.dvaa_image_id != expected_dvaa_image or inspection.dvaa_mount_count != 0
            or inspection.dvaa_port_publications != 0 or inspection.fixture_port_publications != 0):
        errors.append("container_image_or_exposure_mismatch")
    if inspection.dvaa_private_ip != EXPECTED_PEER or inspection.fixture_private_ip != "172.30.77.3":
        errors.append("private_network_identity_mismatch")
    if inspection.proxy_host_bind != "127.0.0.1:17015" or not inspection.isolated_network:
        errors.append("network_isolation_mismatch")
    if inspection.container_visible_url != page_url:
        errors.append("container_visible_fixture_url_mismatch")
    if inspection.observed_collector_peer != EXPECTED_PEER:
        errors.append("collector_peer_not_verified")
    if inspection.fixture_reachable is not True:
        errors.append("fixture_reachability_not_verified")
    if not inspection.cleanup_scope_verified:
        errors.append("cleanup_scope_not_verified")
    return errors


class LabAttemptPreparer:
    """Prepare fresh fixture state; never dispatch GH-WEB-001 or run Docker."""

    def __init__(self, catalog, policy, output_root: Path, *, root=ROOT,
                 inspection_provider=None, output_boundary=None, reviewed_images=None):
        self.catalog, self.policy = catalog, policy
        self.root = Path(root).resolve()
        self.output_root = Path(output_root).absolute()
        boundary = Path(output_boundary).resolve() if output_boundary is not None else self.root / "results"
        if (not self.output_root.is_relative_to(boundary)
                or self.output_root == boundary
                or any(p.is_symlink() for p in (self.output_root, *self.output_root.parents)
                       if p.is_relative_to(boundary))):
            raise LabPreparationError("Lab attempt output must be a non-linked workspace results child.")
        self.output_root.mkdir(parents=True, exist_ok=True)
        self.inspection_provider = inspection_provider
        if reviewed_images is not None and not isinstance(reviewed_images, ReviewedImages):
            raise LabPreparationError("Reviewed image identities are invalid.")
        self.reviewed_images = reviewed_images

    def _assessment(self, selection, *, admit=False):
        if selection.testcase_ids != ["GH-WEB-001"] or selection.asi_categories != ["ASI01"]:
            raise LabPreparationError("Only GH-WEB-001 is supported for lab preparation.")
        preset = self.catalog._targets.get(selection.target.target_id)
        if (preset is None or preset.id != TARGET_ID or preset.endpoint != TARGET_ENDPOINT
                or selection.target.endpoint != TARGET_ENDPOINT):
            raise LabPreparationError("Selected target is not the reviewed isolated-lab proxy.")
        service = AdmissionService(self.catalog, self.policy, root=self.root)
        initial = service.assess(selection)
        asset = initial["asset_sha256"].get("GH-WEB-001")
        if asset:
            key = (selection.target.target_id, selection.target.profile_revision, "GH-WEB-001", asset)
            service.bindings[key] = {"protocol": "openai-chat", "response_observer": True,
                "report_sink": True, "variables": {}, "environment": {},
                "fresh_fixture_factory": True, "collector_recording_executor": True,
                "provenance": "authorized_local_lab_preparation_only"}
        return service.assess(selection, admit=admit)

    def preview(self, selection):
        result = self._assessment(selection)
        errors = static_topology_errors(self.root)
        if self.reviewed_images is None:
            errors.append("reviewed_images_missing")
        return {"workflow_schema_version": "1.0.0", "plan_id": result["plan_id"],
            "preparation_status": "eligible" if result["ready_count"] == 1 and not errors else "blocked",
            "blockers": sorted(set(result["blockers"] + result["items"][0]["blockers"] + errors)),
            "runtime_preflight": "not_checked", "dispatch_available": False,
            "target_request_count": 0}

    def prepare(self, selection):
        assessment = self._assessment(selection, admit=True)
        if not assessment["admitted"] or static_topology_errors(self.root) or self.reviewed_images is None:
            raise LabPreparationError("Target, assets, grant or static lab topology is not ready.")
        asset = assessment["asset_sha256"]["GH-WEB-001"]
        now = datetime.now(timezone.utc)
        grants = [g for g in self.policy.grants if g.authorization_id
            and g.target_id == selection.target.target_id
            and g.profile_revision == selection.target.profile_revision
            and g.policy_ref == selection.target.policy_ref
            and g.testcase_id == "GH-WEB-001" and g.asset_sha256 == asset
            and g.expires_at > now]
        if not grants:
            raise LabPreparationError("Fresh per-attempt execution authorization is required.")
        for grant in grants:
            reservation = self.output_root / ("reserved-auth-" + grant.authorization_id)
            if reservation.exists():
                continue
            attempt_id = uuid4().hex
            try:
                with reservation.open("x", encoding="utf-8") as stream:
                    json.dump({"attempt_id": attempt_id, "plan_id": assessment["plan_id"]}, stream)
            except FileExistsError:
                continue
            directory = self.output_root / attempt_id
            directory.mkdir(exist_ok=False)
            fixture = WebFixture.create(directory / "fixture", FIXTURE_ORIGIN, "attack",
                                        selection.target.target_id, EXPECTED_PEER)
            fixture_path = fixture.directory.as_posix()
            if any(char in fixture_path for char in ("'", "\n", "\r")):
                raise LabPreparationError("Unsupported fixture directory characters.")
            image_values = {"DVAA_IMAGE": self.reviewed_images.dvaa_image,
                "FIXTURE_PYTHON_IMAGE": self.reviewed_images.python_image,
                "PROXY_IMAGE": self.reviewed_images.proxy_image,
                "FIXTURE_STATE_DIR": fixture_path}
            env_text = "\n".join(f"{key}='{value}'" for key,value in image_values.items()) + "\n"
            with (directory / "compose.env").open("x", encoding="utf-8") as stream:
                stream.write(env_text)
            manifest_sha = sha256((fixture.directory / "manifest.json").read_bytes()).hexdigest()
            record = {"schema": 1, "attempt_id": attempt_id, "plan_id": assessment["plan_id"],
                "authorization_id": grant.authorization_id, "target_id": selection.target.target_id,
                "profile_revision": selection.target.profile_revision, "asset_sha256": asset,
                "fixture_manifest_sha256": manifest_sha,
                "compose_env_sha256": sha256((directory / "compose.env").read_bytes()).hexdigest(),
                "created_at": now.isoformat(),
                "status": "prepared_not_attached", "source_provenance": "authorized_local_lab_preparation_only",
                "selection": selection.model_dump(mode="json")}
            with (directory / "attempt.json").open("x", encoding="utf-8") as stream:
                json.dump(record, stream, sort_keys=True)
            return {"workflow_schema_version": "1.0.0", "attempt_id": attempt_id,
                "plan_id": assessment["plan_id"], "preparation_status": "requires_lab_setup",
                "runtime_preflight": "not_checked", "dispatch_available": False,
                "target_request_count": 0}
        raise LabPreparationError("All matching attempt authorizations were already reserved.")

    def preflight(self, attempt_id: str):
        if not re.fullmatch(r"[a-f0-9]{32}", attempt_id):
            raise LabPreparationError("Invalid attempt identity.")
        directory = self.output_root / attempt_id
        record_path = directory / "attempt.json"
        manifest_path = directory / "fixture/manifest.json"
        env_path = directory / "compose.env"
        try:
            safe_file(record_path, self.output_root)
            safe_file(manifest_path, self.output_root)
            safe_file(env_path, self.output_root)
            record = read_json(record_path.read_bytes())
            read_json(manifest_path.read_bytes())  # Reject duplicate/ambiguous keys.
            fixture = WebFixture(directory / "fixture")
        except (OSError, ValueError, TypeError, KeyError):
            raise LabPreparationError("Attempt state is missing or invalid.") from None
        if not isinstance(record, dict):
            raise LabPreparationError("Attempt state is missing or invalid.")
        if (record.get("attempt_id") != attempt_id
                or record.get("status") != "prepared_not_attached"
                or record.get("source_provenance") != "authorized_local_lab_preparation_only"
                or record.get("fixture_manifest_sha256") != sha256(manifest_path.read_bytes()).hexdigest()
                or record.get("compose_env_sha256") != sha256(env_path.read_bytes()).hexdigest()
                or fixture.config["target_id"] != TARGET_ID
                or fixture.config["origin"] != FIXTURE_ORIGIN
                or fixture.config["expected_peer"] != EXPECTED_PEER):
            raise LabPreparationError("Attempt fixture identity or manifest changed.")
        authorization_id = record.get("authorization_id")
        if (not isinstance(authorization_id, str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", authorization_id)):
            raise LabPreparationError("Attempt authorization identity is invalid.")
        reservation_path = self.output_root / ("reserved-auth-" + authorization_id)
        try:
            safe_file(reservation_path, self.output_root)
            reservation = read_json(reservation_path.read_bytes())
        except (OSError, ValueError, TypeError):
            raise LabPreparationError("Attempt reservation is missing or invalid.") from None
        if reservation != {"attempt_id": attempt_id, "plan_id": record.get("plan_id")}:
            raise LabPreparationError("Attempt reservation does not match the fixture.")
        if self.reviewed_images is None:
            raise LabPreparationError("Reviewed image identities are unavailable.")
        expected_env = "\n".join(f"{key}='{value}'" for key,value in {
            "DVAA_IMAGE": self.reviewed_images.dvaa_image,
            "FIXTURE_PYTHON_IMAGE": self.reviewed_images.python_image,
            "PROXY_IMAGE": self.reviewed_images.proxy_image,
            "FIXTURE_STATE_DIR": fixture.directory.as_posix(),
        }.items()) + "\n"
        if env_path.read_text(encoding="utf-8") != expected_env:
            raise LabPreparationError("Attempt Compose binding changed.")
        try:
            selection = AdmissionRequest.model_validate(record["selection"])
            assessment = self._assessment(selection, admit=True)
            valid_grant = any(g.authorization_id == record["authorization_id"]
                and g.target_id == record["target_id"]
                and g.profile_revision == record["profile_revision"]
                and g.asset_sha256 == record["asset_sha256"]
                and g.expires_at > datetime.now(timezone.utc) for g in self.policy.grants)
            if (not assessment["admitted"] or assessment["plan_id"] != record["plan_id"]
                    or assessment["asset_sha256"].get("GH-WEB-001") != record["asset_sha256"]
                    or not valid_grant):
                raise ValueError("stale attempt")
        except (ValueError, KeyError, TypeError):
            raise LabPreparationError("Attempt authorization or testcase assets are stale.") from None
        errors = static_topology_errors(self.root)
        inspection = self.inspection_provider.inspect(attempt_id) if self.inspection_provider else None
        if inspection is not None:
            errors.extend(runtime_inspection_errors(inspection, fixture.directory, fixture.page_url,
                                                    self.reviewed_images.dvaa_image))
        return {"workflow_schema_version": "1.0.0", "attempt_id": attempt_id,
            "static_topology": "consistent" if not static_topology_errors(self.root) else "mismatch",
            "runtime_preflight": "not_checked" if inspection is None else "mock_consistent" if not errors else "mismatch",
            "blockers": sorted(set(errors + (["runtime_inspection_not_available"] if inspection is None else []))),
            "dispatch_available": False, "target_request_count": 0,
            "limitation": "No Docker reachability, peer or mount fact is established without an operator-reviewed runtime inspection."}
