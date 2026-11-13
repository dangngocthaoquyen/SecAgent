"""Read-only network checks and exclusive initialization; never starts Docker."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend" / "src"))
from testing.web_fixture import WebFixture

SUBNETS = ("172.30.77.0/24", "172.30.78.0/24")
RUNTIME_ROOT = ROOT / "results" / "judge-validation" / "asi01-compose"


def assert_no_overlap(prefixes):
    for prefix in prefixes:
        network = ipaddress.ip_network(prefix, strict=False)
        if network.prefixlen == 0 or network.version != 4:
            continue
        for candidate in SUBNETS:
            if network.overlaps(ipaddress.ip_network(candidate)):
                raise ValueError(f"Lab subnet {candidate} overlaps existing route/network {network}; stop and review.")


def read_command(argv):
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=30).stdout


def inspect_networks():
    ids = read_command(["docker", "network", "ls", "-q"]).split()
    prefixes = []
    if ids:
        for network in json.loads(read_command(["docker", "network", "inspect", *ids])):
            prefixes.extend(row["Subnet"] for row in (network.get("IPAM", {}).get("Config") or []) if row.get("Subnet"))
    if os.name == "nt":
        routes = json.loads(read_command(["powershell", "-NoProfile", "-Command",
            "@(Get-NetRoute -AddressFamily IPv4 | Select-Object -ExpandProperty DestinationPrefix) | ConvertTo-Json -Compress"]))
        prefixes.extend(routes if isinstance(routes, list) else [routes])
    assert_no_overlap(prefixes)
    return {"candidates": list(SUBNETS), "checked_prefixes": sorted(set(prefixes)), "overlap": False}


def original_image():
    # Never print full docker inspect: its environment may contain credentials.
    image = read_command(["docker", "inspect", "dvaa-deepseek", "--format", "{{.Image}}"]).strip()
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
        raise ValueError("Original DVAA image identity unavailable.")
    changes = read_command(["docker", "diff", "dvaa-deepseek"]).splitlines()
    if any(line[2:].startswith("/app/src/") or line[2:] in {"/app/package.json", "/app/package-lock.json"} for line in changes):
        raise ValueError("Running DVAA source differs from its image; review before claiming implementation equivalence.")
    return image


def initialize(directory, condition, python_image, proxy_image, dvaa_image, network_review):
    for image in (python_image, proxy_image):
        if not re.fullmatch(r"[A-Za-z0-9_./:-]+@sha256:[a-f0-9]{64}", image):
            raise ValueError("Python and proxy images require repository@sha256:digest references.")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", dvaa_image):
        raise ValueError("DVAA requires the inspected original image ID.")
    directory = Path(directory).resolve()
    if not directory.is_relative_to(RUNTIME_ROOT.resolve()) or directory == RUNTIME_ROOT.resolve():
        raise ValueError("Run directory must be a fresh child of results/judge-validation/asi01-compose.")
    if any(char in str(directory) for char in ("'", "\n", "\r")):
        raise ValueError("Unsupported run-directory characters.")
    directory.mkdir(parents=True, exist_ok=False)
    fixture = WebFixture.create(directory / "fixture", "http://172.30.77.3:8787", condition,
        "dvaa-researchbot-lab", "172.30.77.2")
    values = {"DVAA_IMAGE": dvaa_image, "FIXTURE_PYTHON_IMAGE": python_image,
        "PROXY_IMAGE": proxy_image, "FIXTURE_STATE_DIR": fixture.directory.as_posix()}
    with (directory / "compose.env").open("x", encoding="utf-8") as stream:
        stream.write("\n".join(f"{key}='{value}'" for key, value in values.items()) + "\n")
    sources = [p for p in (ROOT / "backend/src").rglob("*.py")]
    sources += [ROOT / "backend/scripts/serve_asi01_web_fixture.py", *list((ROOT / "fixtures/asi01_web").glob("*.html"))]
    sources += [p for p in (ROOT / "deploy/asi01-lab").iterdir() if p.is_file()]
    provenance = {"dvaa_image": dvaa_image, "python_image": python_image, "proxy_image": proxy_image,
        "network_review": network_review, "fixture_run_id": fixture.config["run_id"],
        "source_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}}
    with (directory / "deployment-provenance.json").open("x", encoding="utf-8") as stream:
        json.dump(provenance, stream, indent=2)
    return directory / "compose.env"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check")
    init = sub.add_parser("init")
    init.add_argument("--run-dir", type=Path, required=True)
    init.add_argument("--condition", choices=["control", "attack"], required=True)
    init.add_argument("--python-image", required=True)
    init.add_argument("--proxy-image", required=True)
    args = parser.parse_args(argv)
    review = inspect_networks()
    if args.command == "check":
        print(json.dumps(review, indent=2))
    else:
        print(initialize(args.run_dir, args.condition, args.python_image, args.proxy_image, original_image(), review))


if __name__ == "__main__":
    main()
