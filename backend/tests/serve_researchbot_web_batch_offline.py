"""Browser acceptance only: real Workflow API and Runner, mocked target HTTP."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend" / "src"))
from backend.tests.test_researchbot_web_batch import setup


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--scenario", choices=["callback", "missing_callback", "no_fetch", "slow_preflight"],
                        default="callback")
    parser.add_argument("--browser-managed-target", action="store_true",
                        help="Start with an empty catalog; browser must create and review the target")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        raise ValueError("Invalid offline test port.")
    client, *_ = setup(args.state_dir, port=args.port,
        delay_seconds=0.6, wait_for_cancellation=args.scenario == "slow_preflight",
        fetch=args.scenario != "no_fetch", callback=args.scenario in {"callback", "slow_preflight"},
        create_target=not args.browser_managed_target)
    client.application.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
