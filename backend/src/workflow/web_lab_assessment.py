"""Two fresh, separately attributed Web fixtures for a restricted lab.

This prepares lab instruments only. It grants no live target execution.
"""

from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import secrets

from testing.web_fixture import WebFixture


def _write_new(path: Path, value: dict):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush()


class WebLabAssessment:
    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self.preflight = WebFixture(self.directory / "preflight")
        self.attack = WebFixture(self.directory / "attack")
        self.identity = json.loads((self.directory / "assessment.json").read_text(encoding="utf-8"))
        if (self.identity.get("schema") != 1
                or not isinstance(self.identity.get("assessment_id"), str)
                or not re.fullmatch(r"[a-f0-9]{32}", self.identity["assessment_id"])
                or self.identity.get("preflight_run_id") != self.preflight.config["run_id"]
                or self.identity.get("attack_run_id") != self.attack.config["run_id"]
                or self.identity.get("target_id") != self.preflight.config["target_id"]
                or self.identity.get("origin") != self.preflight.config["origin"]
                or self.identity.get("expected_peer") != self.preflight.config["expected_peer"]
                or self.preflight.config["condition"] != "control"
                or self.attack.config["condition"] != "attack"
                or self.preflight.config["origin"] != self.attack.config["origin"]
                or self.preflight.config["target_id"] != self.attack.config["target_id"]
                or self.preflight.config["expected_peer"] != self.attack.config["expected_peer"]
                or self.preflight.config["run_id"] == self.attack.config["run_id"]
                or self.preflight.config["canary"] == self.attack.config["canary"]
                or self.identity.get("preflight_manifest_sha256") != sha256(self.preflight.manifest_bytes).hexdigest()
                or self.identity.get("attack_manifest_sha256") != sha256(self.attack.manifest_bytes).hexdigest()
                or self.identity.get("preflight_page_sha256") != sha256(self.preflight.page().encode()).hexdigest()
                or self.identity.get("attack_page_sha256") != sha256(self.attack.page().encode()).hexdigest()):
            raise ValueError("Web lab assessment identity or fixture hashes differ.")

    @classmethod
    def create(cls, parent: Path, origin: str, target_id: str, expected_peer: str):
        parent = Path(parent)
        parent.mkdir(parents=True, exist_ok=True)
        identity = secrets.token_hex(16)
        directory = parent / identity
        directory.mkdir(exist_ok=False)
        control = WebFixture.create(directory / "preflight", origin, "control", target_id, expected_peer)
        attack = WebFixture.create(directory / "attack", origin, "attack", target_id, expected_peer)
        _write_new(directory / "assessment.json", dict(schema=1, assessment_id=identity,
            target_id=target_id, origin=origin, expected_peer=expected_peer,
            preflight_run_id=control.config["run_id"], attack_run_id=attack.config["run_id"],
            preflight_manifest_sha256=sha256(control.manifest_bytes).hexdigest(),
            attack_manifest_sha256=sha256(attack.manifest_bytes).hexdigest(),
            preflight_page_sha256=sha256(control.page().encode()).hexdigest(),
            attack_page_sha256=sha256(attack.page().encode()).hexdigest()))
        return cls(directory)

    @property
    def phase(self):
        return "attack" if (self.directory / "preflight-verified.json").exists() else "preflight"

    @staticmethod
    def _bounded_window(started: datetime, ended: datetime, created_at: datetime):
        if (started.tzinfo is None or ended.tzinfo is None
                or started < created_at or ended < started
                or (ended - started).total_seconds() > 120
                or ended > datetime.now(timezone.utc)):
            raise ValueError("Web lab observation window is invalid or exceeds 120 seconds.")

    def verify_preflight(self, started: datetime, ended: datetime, *, target_request_count: int,
                         target_execution_success: bool):
        if self.phase != "preflight" or target_request_count != 1:
            raise ValueError("Preflight transition requires one accounted target request and a fresh phase.")
        if type(target_execution_success) is not bool:
            raise ValueError("Preflight requires an explicit target execution result.")
        self._bounded_window(started, ended, self.preflight.created_at)
        evidence = self.preflight.evidence(started, ended)
        data = evidence["data"]
        verified = (target_execution_success and data["page_served"] is True
                    and data["receipt_count"] == 0)
        record = dict(schema=1, assessment_id=self.identity["assessment_id"],
            preflight_run_id=self.preflight.config["run_id"],
            purpose="web_fetch_capability_only", security_verdict=None,
            status="verified" if verified else "unverified",
            target_request_count=target_request_count,
            target_execution_success=target_execution_success,
            request_accounting_provenance="caller_supplied_not_network_observed",
            page_visit_provenance="fixture_server_peer_observation",
            started_at=started.isoformat(), ended_at=ended.isoformat(),
            evidence=evidence)
        _write_new(self.directory / "preflight-result.json", record)
        if verified:
            _write_new(self.directory / "preflight-verified.json", dict(
                schema=1, assessment_id=self.identity["assessment_id"],
                preflight_sha256=sha256((self.directory / "preflight-result.json").read_bytes()).hexdigest(),
                activated_at=datetime.now(timezone.utc).isoformat()))
        return record

    def preflight_verified(self):
        marker = self.directory / "preflight-verified.json"
        if not marker.exists():
            return False
        proof = json.loads(marker.read_text(encoding="utf-8"))
        result_path = self.directory / "preflight-result.json"
        result = json.loads(result_path.read_text(encoding="utf-8"))
        return (proof.get("assessment_id") == self.identity["assessment_id"]
            and proof.get("preflight_sha256") == sha256(result_path.read_bytes()).hexdigest()
            and result.get("status") == "verified"
            and result.get("security_verdict") is None
            and result.get("preflight_run_id") == self.preflight.config["run_id"])

    def record_attack_observation(self, started: datetime, ended: datetime, *, target_request_count: int):
        if not self.preflight_verified() or target_request_count != 1:
            raise ValueError("Attack observation requires verified preflight and one accounted request.")
        proof = json.loads((self.directory / "preflight-verified.json").read_text(encoding="utf-8"))
        activated = datetime.fromisoformat(proof["activated_at"])
        self._bounded_window(started, ended, max(self.attack.created_at, activated))
        evidence = self.attack.evidence(started, ended)
        record = dict(schema=1, assessment_id=self.identity["assessment_id"],
            attack_run_id=self.attack.config["run_id"],
            purpose="independent_web_effect_observation", security_verdict=None,
            target_request_count=target_request_count,
            request_accounting_provenance="caller_supplied_not_network_observed",
            page_visit_provenance="fixture_server_peer_observation",
            callback_provenance="fixture_server_peer_observation",
            started_at=started.isoformat(), ended_at=ended.isoformat(), evidence=evidence)
        _write_new(self.directory / "attack-observation.json", record)
        return record
