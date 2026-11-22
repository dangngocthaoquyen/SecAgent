"""Opt-in disposable Docker acceptance of the Web Lab egress boundary.

No DVAA container or agent endpoint is started. Only this script's uniquely
named containers/network are removed. A failure is never treated as a pass.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend" / "src"))
from workflow.web_lab_assessment import WebLabAssessment

LAB = ROOT / "deploy" / "asi01-web-lab"
ORIGIN = "http://172.30.79.3:8787"
PEER = "172.30.79.2"
PROBE_CODE = """
import json,sys,urllib.request,urllib.error
url,method=sys.argv[1:3]
try:
 with urllib.request.urlopen(urllib.request.Request(url,method=method),timeout=2) as response:
  print(json.dumps({'kind':'ok','status':response.status,'redirect':bool(response.headers.get('Location'))}))
except urllib.error.HTTPError as error:
 print(json.dumps({'kind':'http','status':error.code}))
except Exception as error:
 print(json.dumps({'kind':'network','type':type(error).__name__}))
"""
NO_REDIRECT_CODE = """
import json,sys,urllib.request,urllib.error
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args): return None
try:
 urllib.request.build_opener(NoRedirect).open(sys.argv[1],timeout=2)
 print(json.dumps({'status':200}))
except urllib.error.HTTPError as error:
 print(json.dumps({'status':error.code,'location':error.headers.get('Location')}))
"""


def command(*argv, timeout=60, check=True):
    result = subprocess.run(argv, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"Command {argv[:2]} failed ({result.returncode}): "
                           f"{result.stderr[-400:]}")
    return result.stdout.strip()


def probe(container, url, method="GET"):
    return json.loads(command("docker", "exec", "--user", "1000:1000", container,
                              "python", "-c", PROBE_CODE,
                              url, method, timeout=12))


def require(name, condition, results):
    results[name] = bool(condition)
    if not condition:
        raise AssertionError(f"Network acceptance failed: {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="Explicitly create disposable Docker resources")
    args = parser.parse_args()
    if not args.run:
        parser.error("Pass --run for the disposable Docker network acceptance.")
    suffix = uuid4().hex[:12]
    network = "secagent-web-accept-" + suffix
    probe_name = network + "-probe"
    fixture_name = network + "-fixture"
    unrelated_name = network + "-unrelated"
    redirect_name = network + "-redirect"
    owned = []
    results = {}
    try:
        # The production subnet is deliberately used: an overlap fails closed.
        command("docker", "network", "create", "--internal", "--driver", "bridge",
                "--opt", "com.docker.network.bridge.gateway_mode_ipv4=isolated",
                "--subnet", "172.30.79.0/24", network)
        network_state = json.loads(command("docker", "network", "inspect", network))[0]
        require("network_internal_ipv4_only", network_state["Internal"] is True
                and network_state["EnableIPv6"] is False, results)
        with tempfile.TemporaryDirectory(prefix="secagent-web-accept-") as temp:
            assessment = WebLabAssessment.create(Path(temp), ORIGIN, "dvaa-researchbot-lab", PEER)
            command("docker", "build", "-q", "-f", str(LAB / "Dockerfile.guard"),
                    "-t", "secagent-asi01-web-guard:acceptance",
                    "--build-arg", "BASE_IMAGE=nginx:stable-alpine", str(LAB), timeout=180)
            mounts = [
                (ROOT / "backend" / "src", "/workspace/backend/src"),
                (ROOT / "backend" / "scripts" / "serve_asi01_web_lab.py",
                 "/workspace/backend/scripts/serve_asi01_web_lab.py"),
                (ROOT / "fixtures" / "asi01_web", "/workspace/fixtures/asi01_web"),
            ]
            argv = ["docker", "run", "-d", "--name", fixture_name,
                    "--network", network, "--ip", "172.30.79.3", "--user", "10001:10001",
                    "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                    "--read-only"]
            for source, dest in mounts:
                argv += ["--mount", f"type=bind,source={source},target={dest},readonly"]
            argv += ["--mount", f"type=bind,source={assessment.directory},target=/state",
                     "secagent-asi01-fixture:lab", "python",
                     "/workspace/backend/scripts/serve_asi01_web_lab.py", "serve",
                     "--state-dir", "/state", "--bind", "172.30.79.3"]
            command(*argv)
            owned.append(fixture_name)
            if command("docker", "inspect", "--format", "{{.State.Running}}", fixture_name) != "true":
                raise RuntimeError("Fixture container did not start: " +
                    command("docker", "logs", "--tail", "12", fixture_name, check=False)[-500:])
            command("docker", "run", "-d", "--name", unrelated_name,
                    "--network", network, "--ip", "172.30.79.4", "--user", "1000:1000",
                    "--cap-drop", "ALL", "python:3.13-slim", "python", "-m", "http.server",
                    "8787", "--bind", "172.30.79.4", "--directory", "/tmp")
            owned.append(unrelated_name)
            command("docker", "run", "-d", "--name", probe_name,
                    "--network", network, "--ip", PEER, "--user", "10001:10001",
                    "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                    "python:3.13-slim", "python", "-c", "import time; time.sleep(300)")
            owned.append(probe_name)
            command("docker", "run", "--rm", "--network", "container:" + probe_name,
                    "--cap-drop", "ALL", "--cap-add", "NET_ADMIN",
                    "--security-opt", "no-new-privileges:true", "--read-only",
                    "secagent-asi01-web-guard:acceptance", "172.30.79.3", "8787", "1000")
            output_rules = command(
                "docker", "run", "--rm", "--network", "container:" + probe_name,
                "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--entrypoint", "iptables",
                "secagent-asi01-web-guard:acceptance", "-S", "OUTPUT")
            egress_rules = command("docker", "run", "--rm", "--network", "container:" + probe_name,
                "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--entrypoint", "iptables",
                "secagent-asi01-web-guard:acceptance", "-S", "SECAGENT_WEB_EGRESS")
            ipv6_rules = command("docker", "run", "--rm", "--network", "container:" + probe_name,
                "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--entrypoint", "ip6tables",
                "secagent-asi01-web-guard:acceptance", "-S", "OUTPUT")
            routes = command("docker", "run", "--rm", "--network", "container:" + probe_name,
                "--cap-drop", "ALL", "--entrypoint", "ip",
                "secagent-asi01-web-guard:acceptance", "-4", "route")
            require("guard_installed", "-A OUTPUT -j SECAGENT_WEB_EGRESS" in output_rules
                    and "-d 172.30.79.3/32" in egress_rules
                    and "--dport 8787" in egress_rules and "-j REJECT" in egress_rules
                    and "SECAGENT_WEB_EGRESS6" in ipv6_rules, results)
            require("no_default_network_route", "default" not in routes
                    and "172.30.79.0/24" in routes, results)
            row = {}
            for _ in range(10):
                try:
                    row = probe(probe_name, assessment.preflight.page_url)
                    if row.get("kind") == "ok":
                        break
                except RuntimeError:
                    pass
                time.sleep(0.1)
            require("approved_preflight_page", row == {"kind": "ok", "status": 200,
                    "redirect": False}, results)
            require("attack_page_closed_before_preflight", probe(
                probe_name, assessment.attack.page_url) == {"kind": "http", "status": 404}, results)
            require("callback_closed_before_preflight", probe(
                probe_name, ORIGIN + assessment.attack.callback_path) == {
                    "kind": "http", "status": 404}, results)
            started = assessment.preflight.created_at
            ended = datetime.now(timezone.utc)
            preflight = assessment.verify_preflight(started, ended, target_request_count=1,
                target_execution_success=True)
            require("preflight_has_no_security_verdict", preflight["status"] == "verified"
                    and preflight["security_verdict"] is None, results)
            attack_started = datetime.now(timezone.utc)
            require("approved_attack_page", probe(probe_name, assessment.attack.page_url).get(
                    "status") == 200, results)
            require("approved_attack_collector", probe(probe_name,
                    ORIGIN + assessment.attack.callback_path).get("status") == 200, results)
            attack_observation = assessment.record_attack_observation(
                attack_started, datetime.now(timezone.utc), target_request_count=1)
            require("attack_observation_distinct_no_verdict",
                    attack_observation["security_verdict"] is None
                    and attack_observation["evidence"]["data"]["correlation_valid"] is True
                    and attack_observation["attack_run_id"] != preflight["preflight_run_id"], results)
            require("unapproved_method", probe(probe_name,
                    ORIGIN + assessment.attack.callback_path, "POST") == {
                    "kind": "http", "status": 405}, results)
            require("unapproved_route", probe(probe_name, ORIGIN + "/other") == {
                    "kind": "http", "status": 404}, results)
            require("control_page_closed_after_transition", probe(probe_name,
                    assessment.preflight.page_url) == {"kind": "http", "status": 404}, results)
            require("unapproved_port", probe(probe_name,
                    "http://172.30.79.3:8788/")["kind"] == "network", results)
            require("direct_unrelated_container_denied", probe(probe_name,
                    "http://172.30.79.4:8787/")["kind"] == "network", results)
            require("host_gateway_denied", probe(probe_name,
                    "http://172.30.79.1:80/")["kind"] == "network", results)
            require("external_destination_denied", probe(probe_name,
                    "http://1.1.1.1:80/")["kind"] == "network", results)
            require("two_fixtures_independent", assessment.preflight.config["run_id"] !=
                    assessment.attack.config["run_id"] and
                    assessment.preflight.config["canary"] != assessment.attack.config["canary"] and
                    assessment.identity["preflight_page_sha256"] !=
                    assessment.identity["attack_page_sha256"], results)
            new_assessment = WebLabAssessment.create(Path(temp), ORIGIN,
                "dvaa-researchbot-lab", PEER)
            (new_assessment.attack.directory / "events.jsonl").write_bytes(
                (assessment.attack.directory / "events.jsonl").read_bytes())
            require("replayed_receipt_not_attributed", not new_assessment.attack.evidence(
                new_assessment.attack.created_at, datetime.now(timezone.utc))["data"]["correlation_valid"],
                results)
            # Replace the allowed fixture socket with a disposable redirector.
            # The client must follow its 302 and still fail at the denied peer.
            command("docker", "rm", "-f", fixture_name)
            owned.remove(fixture_name)
            redirect_code = (
                "from http.server import BaseHTTPRequestHandler,HTTPServer; "
                "H=type('H',(BaseHTTPRequestHandler,),{"
                "'do_GET':lambda s:(s.send_response(302),"
                "s.send_header('Location','http://172.30.79.4:8787/'),"
                "s.end_headers()),'log_message':lambda *a:None}); "
                "HTTPServer(('172.30.79.3',8787),H).serve_forever()")
            command("docker", "run", "-d", "--name", redirect_name,
                    "--network", network, "--ip", "172.30.79.3", "--user", "1000:1000",
                    "--cap-drop", "ALL", "python:3.13-slim", "python", "-c", redirect_code)
            owned.append(redirect_name)
            for _ in range(15):
                redirect_direct = json.loads(command("docker", "exec", "--user", "1000:1000", probe_name,
                    "python", "-c", NO_REDIRECT_CODE, ORIGIN + "/redirect", timeout=12))
                if redirect_direct.get("status") == 302:
                    break
                time.sleep(0.1)
            require("approved_socket_served_real_redirect", redirect_direct == {
                "status": 302, "location": "http://172.30.79.4:8787/"}, results)
            redirect_result = probe(probe_name, ORIGIN + "/redirect")
            require("http_redirect_to_unapproved_destination_denied",
                    redirect_result["kind"] == "network", results)
            print(json.dumps({"result": "PASS", "checks": results}, sort_keys=True))
    finally:
        for name in reversed(owned):
            command("docker", "rm", "-f", name, check=False)
        command("docker", "network", "rm", network, check=False)


if __name__ == "__main__":
    main()
