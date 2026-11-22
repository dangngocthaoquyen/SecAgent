"""Shared reviewed Web Lab asset loading and TestInput construction."""

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path

from core.models import TestInput
from payloads import PayloadLoader, PayloadRenderer
from testing import TestCaseLoader
from workflow.batch import BatchRejected
from workflow.plans import ROOT, safe_file


def _digest(value) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


WEB_ATTACK = "GH-WEB-001"
WEB_CONTROL = "GH-WEB-C01"
REVIEWED_HASHES = {
    "GH-WEB-C01.yaml": "51a3f7d62820890db7ba2139f6b664e3254962c34456d9a7093ad5d3ba3746b7",
    "GH-WEB-001.yaml": "378650775be6412fcf866b4eb1f50e315d0a927d7001b1b7bb1cb73792b0b8df",
    "goal_hijacking.yaml": "9fe37ad8711d90fee6029564f9db30a18904296fc177400f6cfc9d5d064177cb",
    "control.html": "5442aa1538910b7f56c860d59807b5041de4a04694e4f47100415d6276b69246",
    "attack.html": "02434c7382ab92b764d188969a1f603103917ed75598f44dc10297c509decf94",
}


@dataclass(frozen=True)
class WebAssets:
    control: object
    attack: object
    payloads: dict
    hashes: dict[str, str]
    asset_sha256: str
    input_sha256: str


def load_web_assets(root: Path = ROOT) -> WebAssets:
    root = Path(root).resolve()
    paths = {
        WEB_CONTROL + ".yaml": root / "testcases" / "goal_hijacking" / (WEB_CONTROL + ".yaml"),
        WEB_ATTACK + ".yaml": root / "testcases" / "goal_hijacking" / (WEB_ATTACK + ".yaml"),
        "goal_hijacking.yaml": root / "payload" / "goal_hijacking.yaml",
        "control.html": root / "fixtures" / "asi01_web" / "control.html",
        "attack.html": root / "fixtures" / "asi01_web" / "attack.html",
    }
    for path in paths.values():
        safe_file(path, root)
    hashes = {name: sha256(path.read_bytes()).hexdigest() for name, path in paths.items()}
    if hashes != REVIEWED_HASHES:
        raise BatchRejected("Reviewed Web testcase, payload or fixture asset changed.")
    control = TestCaseLoader().load(paths[WEB_CONTROL + ".yaml"])
    attack = TestCaseLoader().load(paths[WEB_ATTACK + ".yaml"])
    payloads = PayloadLoader().load_repository(paths["goal_hijacking.yaml"])
    if (
        control.id != WEB_CONTROL
        or attack.id != WEB_ATTACK
        or control.evaluation.strategy != "semantic"
        or control.evaluation.rules
        or attack.evaluation.strategy != "hybrid"
        or len(attack.evaluation.rules) != 1
        or attack.evaluation.rules[0].type != "collector_receipt"
        or attack.evaluation.rules[0].verdict.value != "FAIL"
        or attack.evaluation.semantic is None
        or attack.evaluation.semantic.trusted_context.get("collector_verification_required") is not True
        or control.payload_refs != ["GH-PWEB-C01"]
        or attack.payload_refs != ["GH-PWEB-001"]
        or any(ref not in payloads for ref in (*control.payload_refs, *attack.payload_refs))
    ):
        raise BatchRejected("Reviewed Web evaluation contract changed.")
    return WebAssets(
        control,
        attack,
        payloads,
        hashes,
        _digest([hashes, "web_attack_with_separate_capability_preflight_v1"]),
        _digest([hashes["goal_hijacking.yaml"], "fresh_fixture_bound_at_execution_v1"]),
    )


def _input(bound, payloads, execution_id: str) -> TestInput:
    payload = payloads[bound.payload_refs[0]]
    prompt = PayloadRenderer().render(payload, bound.variables)
    if "{{" in prompt or "REQUIRES_" in prompt or "/unconfigured" in prompt:
        raise BatchRejected("Web input was not fully bound to a fresh fixture.")
    return TestInput(id="web-batch-" + execution_id, prompt=prompt, payload_ref=payload.id)
