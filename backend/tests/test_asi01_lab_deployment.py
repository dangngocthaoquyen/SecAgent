"""Offline deployment contracts; docker compose config never starts containers."""
import importlib.util
from importlib.metadata import version, requires
import json
import os
import re
import shutil
import subprocess

import pytest
import yaml
from packaging.requirements import Requirement

from test_official_asi01_runner import ROOT
from testing.web_fixture import WebFixture

DEPLOY = ROOT / "deploy/asi01-lab"
COMPOSE = yaml.safe_load((DEPLOY / "compose.yaml").read_text())
spec = importlib.util.spec_from_file_location("lab_prepare", ROOT / "backend/scripts/prepare_asi01_lab.py")
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)
PYTHON = "python@sha256:" + "a" * 64
NGINX = "nginx@sha256:" + "b" * 64
DVAA = "sha256:" + "c" * 64


def init(tmp_path, monkeypatch, condition="control"):
    monkeypatch.setattr(prepare, "RUNTIME_ROOT", tmp_path)
    return prepare.initialize(tmp_path / condition, condition, PYTHON, NGINX, DVAA,
        {"candidates": list(prepare.SUBNETS), "checked_prefixes": [], "overlap": False})


def test_only_proxy_is_dual_homed_and_published():
    services = COMPOSE["services"]
    assert set(services) == {"dvaa", "fixture", "proxy"}
    assert set(services["dvaa"]["networks"]) == {"lab"}
    assert set(services["fixture"]["networks"]) == {"lab"}
    assert set(services["proxy"]["networks"]) == {"lab", "access"}
    assert all("ports" not in services[s] for s in ("dvaa", "fixture"))
    assert services["proxy"]["ports"] == [{"target": 8080, "published": "17015", "host_ip": "127.0.0.1", "protocol": "tcp"}]
    assert services["proxy"]["sysctls"]["net.ipv4.ip_forward"] == "0"
    assert all("ALL" in s["cap_drop"] for s in services.values())


def test_internal_isolated_network_has_no_original_resource_dependencies():
    lab, access = COMPOSE["networks"]["lab"], COMPOSE["networks"]["access"]
    assert COMPOSE["name"] == "secagent-asi01-lab"
    assert lab["internal"] is True
    assert lab["driver_opts"]["com.docker.network.bridge.gateway_mode_ipv4"] == "isolated"
    assert not access.get("internal", False)
    assert all(n["name"].startswith("secagent-asi01-lab-") and not n.get("external", False)
               for n in COMPOSE["networks"].values())
    dvaa = COMPOSE["services"]["dvaa"]
    assert dvaa["environment"] == {"DVAA_ALLOW_INTERNAL_FETCH": "1", "DVAA_RESEARCH_CACHE": "off"}
    assert dvaa["pull_policy"] == "never"
    assert not any(key in dvaa for key in ("volumes", "env_file", "secrets", "command", "entrypoint", "container_name"))


def test_fixture_has_only_state_writable_and_no_credentials():
    service = COMPOSE["services"]["fixture"]
    assert service["read_only"] is True and service["user"] == "10001:10001"
    writable = [v for v in service["volumes"] if not v.get("read_only", False)]
    assert len(writable) == 1 and writable[0]["target"] == "/state"
    assert writable[0]["bind"]["create_host_path"] is False
    assert len(service["tmpfs"]) == 1 and service["tmpfs"][0].startswith("/tmp:")
    assert set(service["environment"]) == {"PYTHONDONTWRITEBYTECODE", "PYTHONUNBUFFERED"}
    assert all(v["source"].startswith(("../../backend/src", "../../backend/scripts/serve_asi01_web_fixture.py", "../../fixtures/asi01_web", "${FIXTURE_STATE_DIR")) for v in service["volumes"])


def test_pinned_fixture_dependencies_match_current_tested_environment_and_closure():
    lines = (DEPLOY / "requirements.fixture.txt").read_text().splitlines()
    packages = [Requirement(line) for line in lines if line and not line.startswith("#")]
    canonical = lambda name: name.lower().replace("_", "-")
    names = {canonical(p.name) for p in packages}
    assert {"httpx", "pydantic", "pyyaml"} <= names and "pytest" not in names
    for package in packages:
        assert str(package.specifier) == "==" + version(package.name)
        for dependency in requires(package.name) or []:
            dep = Requirement(dependency)
            if dep.marker is None or dep.marker.evaluate({"extra": "", "sys_platform": "linux", "os_name": "posix"}):
                assert canonical(dep.name) in names
    dockerfile = (DEPLOY / "Dockerfile.fixture").read_text()
    assert "FROM ${PYTHON_IMAGE}" in dockerfile and "pip check" in dockerfile
    assert "COPY ." not in dockerfile and "requirements.fixture.txt" in dockerfile
    assert (DEPLOY / ".dockerignore").read_text().splitlines()[0] == "*"


def test_nginx_allowlist_and_fixed_upstream_static_contract():
    text = re.sub(r"#.*", "", (DEPLOY / "nginx.conf").read_text())
    tokens = re.findall(r'"[^"\n]*"|[{};]|[^{};\s]+', text)
    # Structural delimiter/statement verification; nginx -t remains a runtime gate.
    depth = 0
    for token in tokens:
        if token == "{": depth += 1
        if token == "}": depth -= 1
        assert depth >= 0
    assert depth == 0
    assert re.findall(r"listen\s+([^;]+);", text) == ["172.30.78.2:8080"]
    assert re.findall(r"location\s+=\s+(\S+)", text) == ["/health", "/v1/chat/completions"]
    assert re.findall(r"proxy_pass\s+([^;]+);", text) == ["http://researchbot/health", "http://researchbot/v1/chat/completions"]
    assert "server 172.30.77.2:7015;" in text
    assert "location / { return 404; }" in text
    assert "limit_except GET { deny all; }" in text and "limit_except POST { deny all; }" in text
    assert "proxy_next_upstream off;" in text
    assert "access_log off;" in text
    assert "resolver " not in text and "proxy_pass $" not in text and "172.30.77.3" not in text


@pytest.mark.parametrize("prefix", ["172.30.77.0/24", "172.30.78.2/32", "172.16.0.0/12"])
def test_overlaps_fail_closed(prefix):
    with pytest.raises(ValueError, match="overlap"):
        prepare.assert_no_overlap([prefix])


def test_reviewed_visible_networks_do_not_overlap():
    prepare.assert_no_overlap(["172.17.0.0/16", "172.20.10.0/24", "192.168.13.0/24", "0.0.0.0/0"])


def test_network_inspection_handles_no_ipam_and_windows_routes(monkeypatch):
    monkeypatch.setattr(prepare.os, "name", "nt")
    calls = []
    def read(args):
        calls.append(args)
        if args[:3] == ["docker", "network", "ls"]: return "one two"
        if args[:3] == ["docker", "network", "inspect"]:
            return json.dumps([{"IPAM": {"Config": None}}, {"IPAM": {"Config": [{"Subnet": "172.17.0.0/16"}]}}])
        return '["0.0.0.0/0","192.168.13.0/24"]'
    monkeypatch.setattr(prepare, "read_command", read)
    assert prepare.inspect_networks()["overlap"] is False
    assert all("run" not in call and "up" not in call for call in calls)


def test_fresh_state_binds_existing_testcase_and_never_reuses_run(tmp_path, monkeypatch):
    env = init(tmp_path, monkeypatch, "attack")
    fixture = WebFixture(env.parent / "fixture")
    assert fixture.config["expected_peer"] == "172.30.77.2"
    assert fixture.config["target_id"] == "dvaa-researchbot-lab"
    from testing import TestCaseLoader
    case = fixture.bind(TestCaseLoader().load(ROOT / "testcases/goal_hijacking/GH-WEB-001.yaml"), "dvaa-researchbot-lab")
    assert case.evaluation.rules[0].parameters["run_id"] == fixture.config["run_id"]
    provenance = json.loads((env.parent / "deployment-provenance.json").read_text())
    assert provenance["dvaa_image"] == DVAA and provenance["source_sha256"]
    assert "DEEPSEEK" not in env.read_text() and fixture.config["canary"] not in env.read_text()
    with pytest.raises(FileExistsError): init(tmp_path, monkeypatch, "attack")


def test_run_directory_and_image_validation_happen_before_writing(tmp_path, monkeypatch):
    monkeypatch.setattr(prepare, "RUNTIME_ROOT", tmp_path / "allowed")
    with pytest.raises(ValueError):
        prepare.initialize(tmp_path / "outside", "attack", PYTHON, NGINX, DVAA, {})
    with pytest.raises(ValueError):
        prepare.initialize(tmp_path / "allowed" / "new", "attack", "python:latest", NGINX, DVAA, {})
    assert not (tmp_path / "allowed").exists()


def test_original_inspection_rejects_source_mutations_without_exposing_env(monkeypatch):
    calls = []
    def read(args):
        calls.append(args)
        return DVAA if "inspect" in args else "C /app/src/index.js"
    monkeypatch.setattr(prepare, "read_command", read)
    with pytest.raises(ValueError, match="source differs"):
        prepare.original_image()
    assert calls[0][-1] == "{{.Image}}"


def test_compose_cli_configuration_validation_without_starting_services(tmp_path, monkeypatch):
    if os.environ.get("SECAGENT_NO_DOCKER") == "1":
        pytest.skip("Docker execution disabled by this offline verification scope")
    if not shutil.which("docker"):
        pytest.skip("Docker Compose CLI unavailable; only static contracts checked")
    env = init(tmp_path, monkeypatch)
    result = subprocess.run(["docker", "compose", "--env-file", str(env), "-f", str(DEPLOY / "compose.yaml"),
        "config", "--format", "json"], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["services"]["dvaa"]["image"] == DVAA
    assert data["services"]["proxy"]["image"] == NGINX
    assert data["services"]["fixture"]["build"]["args"]["PYTHON_IMAGE"] == PYTHON
    port = data["services"]["proxy"]["ports"][0]
    assert port["host_ip"] == "127.0.0.1" and port["published"] == "17015"
    assert data["services"]["fixture"]["volumes"][-1]["source"].replace("\\", "/").endswith("/control/fixture")
