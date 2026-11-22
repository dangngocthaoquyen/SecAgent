"""Operator-owned restricted Docker Web Lab lifecycle; no agent requests here."""
from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.request

from workflow.plans import ROOT
from workflow.web_lab_assessment import WebLabAssessment


ORIGIN = "http://172.30.79.3:8787"
TARGET = "dvaa-researchbot-web-lab"
PEER = "172.30.79.2"
SUBNETS = (ipaddress.ip_network("172.30.79.0/24"), ipaddress.ip_network("172.30.80.0/24"))
COMPOSE = ROOT / "deploy" / "asi01-web-lab" / "compose.yaml"
PROJECT = "secagent-asi01-web-lab"
INGRESS = "http://127.0.0.1:17016"
CHAT = INGRESS + "/v1/chat/completions"
SERVICES = ("netns", "egress_guard", "researchbot", "fixture", "ingress")


def output(*argv):
    return subprocess.run(argv, capture_output=True, text=True, check=True, timeout=30).stdout.strip()


def check_networks():
    ids = output("docker", "network", "ls", "-q").split()
    if not ids:
        return
    for item in json.loads(output("docker", "network", "inspect", *ids)):
        for config in item.get("IPAM", {}).get("Config") or []:
            if config.get("Subnet"):
                network = ipaddress.ip_network(config["Subnet"], strict=False)
                if any(network.overlaps(lab) for lab in SUBNETS):
                    raise ValueError("Web Lab subnet overlaps a running Docker network; stop and review.")
    if os.name == "nt":
        routes = json.loads(output("powershell", "-NoProfile", "-Command",
            "@(Get-NetRoute -AddressFamily IPv4 | Select-Object -ExpandProperty DestinationPrefix) | ConvertTo-Json -Compress"))
        for prefix in routes if isinstance(routes, list) else [routes]:
            network = ipaddress.ip_network(prefix, strict=False)
            if network.prefixlen and any(network.overlaps(lab) for lab in SUBNETS):
                raise ValueError("Web Lab subnet overlaps a host route; stop and review.")


def reviewed_image(reference):
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", reference):
        raise ValueError("Lab service images require a reviewed local sha256 image ID.")
    if output("docker", "image", "inspect", reference, "--format", "{{.Id}}") != reference:
        raise ValueError("Reviewed image ID is not present locally.")
    return reference


def reviewed_base(reference):
    if not re.fullmatch(r"[A-Za-z0-9_./:-]+@sha256:[a-f0-9]{64}", reference):
        raise ValueError("Guard base image requires a reviewed repository@sha256 digest.")
    output("docker", "image", "inspect", reference, "--format", "{{.Id}}")
    return reference


def initialize(parent, dvaa_image, fixture_image, proxy_image, guard_base_image):
    check_networks()
    images = dict(DVAA_IMAGE=reviewed_image(dvaa_image),
                  FIXTURE_IMAGE=reviewed_image(fixture_image),
                  PROXY_IMAGE=reviewed_image(proxy_image),
                  GUARD_BASE_IMAGE=reviewed_base(guard_base_image))
    parent = Path(parent).resolve()
    if parent.is_relative_to(ROOT) or any(c in str(parent) for c in "'\r\n"):
        raise ValueError("Use an operator-owned output directory outside the repository.")
    assessment = WebLabAssessment.create(parent, ORIGIN, TARGET, PEER)
    with (assessment.directory / "compose.env").open("x", encoding="utf-8") as stream:
        for key, value in (images | {"WEB_LAB_STATE_DIR": assessment.directory.as_posix()}).items():
            stream.write(f"{key}='{value}'\n")
    return assessment.directory


def _command(*argv, timeout=120):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError("Restricted Web Lab Docker operation failed.")
    return result.stdout.strip()


class DockerWebLabRuntime:
    provenance = "restricted_dvaa_lab"

    def __init__(self, state_parent: Path, *, dvaa_image: str, fixture_image: str,
                 proxy_image: str, guard_base_image: str):
        self.state_parent = Path(state_parent).resolve()
        if self.state_parent.is_relative_to(ROOT.resolve()) or self.state_parent == Path(self.state_parent.anchor):
            raise ValueError("Web Lab state must be operator-owned outside the repository.")
        self.images = dict(dvaa_image=dvaa_image, fixture_image=fixture_image,
                           proxy_image=proxy_image, guard_base_image=guard_base_image)
        self.verified_at = None
        self._verified_identity = None
        self.last_guard_image_id = None

    def identity(self):
        files = [COMPOSE, COMPOSE.parent / "egress-guard.sh", COMPOSE.parent / "Dockerfile.guard",
                 COMPOSE.parent / "nginx.conf", ROOT / "backend/scripts/serve_asi01_web_lab.py",
                 ROOT / "backend/src/workflow/web_lab_assessment.py"]
        return dict(images=self.images, target_id=TARGET, endpoint=CHAT, fixture_origin=ORIGIN,
                    expected_peer=PEER,
                    source_sha256={str(path.relative_to(ROOT)): sha256(path.read_bytes()).hexdigest()
                                   for path in files})

    def _ensure_absent(self):
        names = _command("docker", "ps", "-a", "--filter", f"label=com.docker.compose.project={PROJECT}",
                         "--format", "{{.ID}}")
        if names:
            raise RuntimeError("An existing Web Lab project requires operator review.")

    def _inspect(self, service):
        return json.loads(_command("docker", "inspect", f"{PROJECT}-{service}-1"))[0]

    def _verify(self, assessment):
        rows = {name: self._inspect(name) for name in SERVICES}
        guard, target, holder, fixture, ingress = (rows[name] for name in
            ("egress_guard", "researchbot", "netns", "fixture", "ingress"))
        if (guard["State"]["ExitCode"] != 0 or target["State"]["Running"] is not True
                or holder["State"]["Running"] is not True or fixture["State"]["Running"] is not True
                or ingress["State"]["Running"] is not True
                or guard["State"]["FinishedAt"] >= target["State"]["StartedAt"]
                or target["Image"] != self.images["dvaa_image"]
                or fixture["Image"] != self.images["fixture_image"]
                or ingress["Image"] != self.images["proxy_image"]
                or holder["Image"] != self.images["proxy_image"]):
            raise RuntimeError("Web Lab startup or reviewed image identity is unverified.")
        if guard["Image"] != _command("docker", "image", "inspect",
                "secagent-asi01-web-guard:lab", "--format", "{{.Id}}"):
            raise RuntimeError("Web Lab guard image identity differs from the reviewed build.")
        self.last_guard_image_id = guard["Image"]
        if (target["Config"]["User"] != "1000:1000"
                or target["HostConfig"]["Privileged"]
                or target["HostConfig"]["ReadonlyRootfs"] is not True
                or target["HostConfig"]["CapDrop"] != ["ALL"]
                or target["Mounts"] or holder["Mounts"] or guard["Mounts"]
                or target["HostConfig"]["NetworkMode"] != "container:" + holder["Id"]):
            raise RuntimeError("Web Lab target process boundary differs from review.")
        fixture_mounts = {m["Destination"]: m for m in fixture["Mounts"]}
        expected_fixture_mounts = {"/workspace/backend/src", "/workspace/backend/scripts/serve_asi01_web_lab.py",
                                   "/workspace/fixtures/asi01_web", "/state"}
        ingress_mounts = {m["Destination"]: m for m in ingress["Mounts"]}
        if (set(fixture_mounts) != expected_fixture_mounts
                or any(fixture_mounts[path]["RW"] for path in expected_fixture_mounts - {"/state"})
                or fixture_mounts["/state"]["RW"] is not True
                or Path(fixture_mounts["/state"]["Source"]).resolve() != assessment.directory.resolve()
                or set(ingress_mounts) != {"/etc/nginx/nginx.conf"}
                or ingress_mounts["/etc/nginx/nginx.conf"]["RW"] is not False):
            raise RuntimeError("Web Lab mounts differ from the narrow fixture and ingress contract.")
        ports = ingress["HostConfig"]["PortBindings"]
        if ports != {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "17016"}]}:
            raise RuntimeError("Web Lab ingress is not bound only to host loopback.")
        private = json.loads(_command("docker", "network", "inspect", "secagent-asi01-web-private"))[0]
        access = json.loads(_command("docker", "network", "inspect", "secagent-asi01-web-access"))[0]
        if (private["Internal"] is not True or private["EnableIPv6"] is not False
                or access["Internal"] is True
                or len(holder["NetworkSettings"]["Networks"]) != 1
                or set(ingress["NetworkSettings"]["Networks"]) !=
                   {"secagent-asi01-web-private", "secagent-asi01-web-access"}
                or holder["NetworkSettings"]["Networks"]["secagent-asi01-web-private"]["IPAddress"] != PEER
                or fixture["NetworkSettings"]["Networks"]["secagent-asi01-web-private"]["IPAddress"] != "172.30.79.3"):
            raise RuntimeError("Web Lab network attachments differ from review.")
        guard_image = guard["Image"]
        namespace = "container:" + holder["Id"]
        def rules(binary, chain):
            return _command("docker", "run", "--rm", "--network", namespace,
                "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--entrypoint", binary,
                guard_image, "-S", chain)
        ipv4 = rules("iptables", "OUTPUT")
        allowed = rules("iptables", "SECAGENT_WEB_EGRESS")
        ipv6 = rules("ip6tables", "OUTPUT")
        if ("-A OUTPUT -j SECAGENT_WEB_EGRESS" not in ipv4
                or "-d 172.30.79.3/32" not in allowed
                or "--dport 8787" not in allowed
                or "-A SECAGENT_WEB_EGRESS -j REJECT" not in allowed
                or "-A OUTPUT -j SECAGENT_WEB_EGRESS6" not in ipv6):
            raise RuntimeError("Web Lab egress policy differs from review.")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        healthy = False
        for _ in range(30):
            try:
                with opener.open(INGRESS + "/health", timeout=2) as response:
                    healthy = response.status == 200 and len(response.read(1025)) <= 1024
                if healthy:
                    break
            except OSError:
                pass
            time.sleep(0.2)
        if not healthy:
            raise RuntimeError("Web Lab health response is invalid.")
        # TCP only: startup verification must not fetch either testcase page.
        socket_code = ("const n=require('net');const s=n.connect({host:'172.30.79.3',port:8787});"
                       "s.setTimeout(2000);s.on('connect',()=>{console.log('ok');s.destroy()});"
                       "s.on('error',()=>process.exit(2));s.on('timeout',()=>process.exit(3))")
        if _command("docker", "exec", f"{PROJECT}-researchbot-1", "node", "-e", socket_code,
                    timeout=8) != "ok" or assessment.preflight.rows() or assessment.attack.rows():
            raise RuntimeError("Web Lab fixture reachability or fresh observation state is invalid.")

    @contextmanager
    def open(self):
        self.state_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        marker = self.state_parent / ".active-web-lab"
        with marker.open("x", encoding="utf-8") as stream:
            stream.write(datetime.now(timezone.utc).isoformat())
        started = False
        cleanup_ok = True
        env_file = None
        try:
            self._ensure_absent()
            directory = initialize(self.state_parent, self.images["dvaa_image"],
                self.images["fixture_image"], self.images["proxy_image"],
                self.images["guard_base_image"])
            env_file = directory / "compose.env"
            argv = ("docker", "compose", "-f", str(COMPOSE), "--env-file", str(env_file))
            started = True
            _command(*argv, "up", "-d", "--build", timeout=180)
            assessment = WebLabAssessment(directory)
            self._verify(assessment)
            yield assessment
        finally:
            if started and env_file is not None:
                try:
                    _command("docker", "compose", "-f", str(COMPOSE), "--env-file", str(env_file),
                             "down", timeout=90)
                except RuntimeError:
                    cleanup_ok = False
            if cleanup_ok:
                marker.unlink(missing_ok=True)
            else:
                raise RuntimeError("Web Lab teardown failed; claim retained for operator review.")

    def verify_startup(self):
        identity = self.identity()
        with self.open() as assessment:
            # Startup-only benign route checks use a disposable assessment.
            # They never authorize a testcase or become preflight evidence.
            probe = ("const http=require('http');const req=http.get(process.argv[1],r=>{"
                     "console.log(r.statusCode);r.resume()});"
                     "req.setTimeout(2000,()=>req.destroy());"
                     "req.on('error',()=>process.exit(2))")
            def status(url):
                return _command("docker", "exec", f"{PROJECT}-researchbot-1",
                    "node", "-e", probe, url, timeout=8)
            if (status(assessment.preflight.page_url) != "200"
                    or status(ORIGIN + "/collector/invalid") != "404"
                    or len(assessment.preflight.rows()) != 1
                    or assessment.preflight.rows()[0]["peer_matches"] is not True
                    or assessment.attack.rows()):
                raise RuntimeError("Web Lab fixture or collector route diagnostic failed.")
        self._verified_identity = identity
        self.verified_at = datetime.now(timezone.utc)

    def ready(self):
        # A fresh lab is fully reverified for every run. The startup proof only
        # gates UI admission within this process and is invalidated by source
        # or image configuration changes, not by ordinary operator dwell time.
        return self.verified_at is not None and self._verified_identity == self.identity()
