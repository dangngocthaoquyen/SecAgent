"""Create one non-secret, two-fixture Web Lab assessment; never starts Docker."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend" / "src"))
from workflow.web_lab_runtime import (
    ORIGIN,
    PEER,
    SUBNETS,
    TARGET,
    check_networks,
    initialize,
    output,
    reviewed_base,
    reviewed_image,
)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-parent", type=Path, required=True)
    parser.add_argument("--dvaa-image", required=True)
    parser.add_argument("--fixture-image", required=True)
    parser.add_argument("--proxy-image", required=True)
    parser.add_argument("--guard-base-image", required=True)
    args = parser.parse_args(argv)
    directory = initialize(args.state_parent, args.dvaa_image, args.fixture_image,
                           args.proxy_image, args.guard_base_image)
    print(json.dumps({"assessment_directory": str(directory),
                      "compose_env": str(directory / "compose.env"),
                      "phase": "preflight", "live_dispatch_enabled": False}))


if __name__ == "__main__":
    main()
