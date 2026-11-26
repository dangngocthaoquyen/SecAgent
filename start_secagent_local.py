"""Start SecAgent's three loopback services with one in-memory local credential."""
import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
import webbrowser


ROOT = Path(__file__).resolve().parent
FRONTEND = ROOT / "frontend"
BACKEND = ROOT / "backend" / "src"
SEED = ROOT / "configs" / "workflow" / "authorized-targets.example.json"
RUNS = ROOT / "results" / "local-controlled-runs"


def available_port(preferred: int, reserved: set[int]) -> int:
    for choice in (preferred, 0):
        try:
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", choice))
                port = listener.getsockname()[1]
                if port not in reserved:
                    return port
        except OSError:
            continue
    raise RuntimeError("No free loopback port is available.")


def local_data_dir(override: str | None) -> Path:
    if override:
        path = Path(override).absolute()
    elif os.name == "nt":
        path = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "SecAgent"
    else:
        path = Path.home() / ".local" / "share" / "secagent"
    if path.resolve().is_relative_to(ROOT):
        raise ValueError("Local application data must be outside the repository.")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def runtime_settings(data: Path, override: str | None) -> dict:
    """Optional operator-owned references, never credentials or approvals."""
    path = Path(override).absolute() if override else data / 'runtime.json'
    if not path.exists():
        if override:
            raise ValueError('Runtime configuration is unavailable.')
        return {}
    if not path.is_file() or path.is_symlink() or path.resolve().is_relative_to(ROOT) or path.stat().st_size > 16384:
        raise ValueError('Runtime configuration must be a bounded operator-owned file outside the repository.')
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
        allowed = {'schema_version', 'judge_config', 'evidence_policy', 'mcp_action_catalog',
                   'reviewed_mcp_catalog_sha256', 'dvaa_mcp_receipt_root', 'agent_bridge_config',
                   'target_catalog'}
        if not isinstance(value, dict) or set(value) - allowed or value.get('schema_version') != '1.0.0':
            raise ValueError()
        for key in allowed - {'schema_version'}:
            if key in value and value[key] is not None and (not isinstance(value[key], str) or not value[key]):
                raise ValueError()
        return value
    except (ValueError, UnicodeError, OSError):
        raise ValueError('Runtime configuration is invalid.') from None


def resolve_target_credential_env_names(catalog_path: Path, target_data_dir: Path) -> set[str]:
    """Read registered Target credential environment variable names from the active catalog configuration.

    Returns only validated env var reference names (never values). Checks both
    the active seed catalog file and any persisted managed catalog state file.
    """
    sys.path.insert(0, str(BACKEND))
    from workflow.catalog import load_catalog, read_json
    from workflow.management import ManagedState

    env_names: set[str] = set()
    seed_catalog = load_catalog(catalog_path)
    env_names.update(seed_catalog._config.credential_aliases.values())

    state_file = target_data_dir / "target-catalog.json"
    if state_file.exists() and state_file.is_file() and not state_file.is_symlink() and state_file.stat().st_size <= 262144:
        try:
            raw_state = read_json(state_file.read_bytes())
            if isinstance(raw_state, dict) and "archived" in raw_state:
                raw_state = {k: v for k, v in raw_state.items() if k != "archived"}
            state = ManagedState.model_validate(raw_state)
            env_names.update(state.catalog.credential_aliases.values())
        except Exception:
            # Let workflow.api perform authoritative catalog state validation on startup.
            pass
    return env_names


def reporting_manifest(data: Path) -> Path:
    RUNS.mkdir(parents=True, exist_ok=True, mode=0o700)
    manifest = data / "reporting-local.json"
    expected = {"dataset_schema_version": "1.0.0",
                "allowed_roots": {"controlled": str(RUNS)},
                "reports": [], "verification_jobs": [],
                "controlled_runs_root": "controlled"}
    if manifest.exists():
        if manifest.is_symlink() or json.loads(manifest.read_text(encoding="utf-8")) != expected:
            raise ValueError("Existing local reporting selection differs from the expected controlled-run root.")
    else:
        temporary = data / (".reporting-" + secrets.token_hex(8) + ".tmp")
        with temporary.open("x", encoding="utf-8") as stream:
            json.dump(expected, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, manifest)
    return manifest


def ready(url: str, predicate, *, attempts: int = 60) -> bool:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for _ in range(attempts):
        try:
            with opener.open(url, timeout=1) as response:
                if predicate(response):
                    return True
        except (OSError, ValueError):
            pass
        time.sleep(0.25)
    return False


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", help="Optional local operator data directory; default is the user's application data")
    parser.add_argument("--catalog", help="Optional operator-owned Target catalog JSON (defines registered credential aliases)")
    parser.add_argument("--sync-credential-aliases", action="store_true",
                        help="Explicitly register newly added credential aliases from --catalog into an existing managed target catalog (strictly additive, atomic backup)")
    parser.add_argument("--runtime-config", help="Optional operator-owned runtime references; defaults to runtime.json in the local data directory")
    parser.add_argument("--no-browser", action="store_true", help="Print the URL without opening a browser")
    parser.add_argument("--enable-custom-imported-batch", action="store_true",
                        help="Enable Generic Custom Imported Testcase batch (Offline Mock by default)")
    parser.add_argument("--enable-imported-live-local", action="store_true",
                        help="Permit explicitly selected Live Local imported batches for reviewed loopback chat targets")
    parser.add_argument("--judge-config", help="Operator-owned non-secret RunnerEvaluationConfig JSON; explicitly enables Hybrid Judge")
    parser.add_argument("--evidence-policy", help="Operator-owned non-secret HTTP evidence endpoint allowlist; collection remains manual")
    parser.add_argument("--mcp-action-catalog", help="Structured MCP action case catalog; tool calls still require explicit confirmation")
    parser.add_argument("--reviewed-mcp-catalog-sha256", help="Pin an independently reviewed MCP action catalog by exact SHA-256")
    parser.add_argument("--dvaa-mcp-receipt-root", help="Optional instrumented DVAA receipt directory")
    parser.add_argument("--agent-bridge-config", help="Operator-owned, SHA-pinned Promptfoo Agent provider bridge configuration")
    args = parser.parse_args(argv)
    data = local_data_dir(args.data_dir)
    settings = runtime_settings(data, args.runtime_config)
    for key in ('judge_config','evidence_policy','mcp_action_catalog',
                'reviewed_mcp_catalog_sha256','dvaa_mcp_receipt_root','agent_bridge_config'):
        if getattr(args, key) is None and settings.get(key):
            setattr(args, key, settings[key])
    if args.catalog is None and settings.get('target_catalog'):
        args.catalog = settings['target_catalog']
    catalog_path = Path(args.catalog).absolute() if args.catalog else SEED
    if not catalog_path.is_file() or catalog_path.is_symlink():
        raise ValueError("Target catalog configuration is unavailable.")
    unified = not args.enable_custom_imported_batch
    if args.enable_imported_live_local and not (args.enable_custom_imported_batch or unified):
        parser.error("Live Local requires --enable-custom-imported-batch.")
    if args.judge_config and not (unified or args.enable_custom_imported_batch or args.mcp_action_catalog):
        parser.error("Hybrid Judge requires an enabled evaluation workflow.")
    if args.dvaa_mcp_receipt_root and not args.mcp_action_catalog:
        parser.error("DVAA receipt collection requires --mcp-action-catalog.")
    processes = []
    try:
        node = shutil.which("node")
        vite = FRONTEND / "node_modules" / "vite" / "bin" / "vite.js"
        if not node or not vite.is_file() or not SEED.is_file():
            raise RuntimeError("Python and Node dependencies must be installed before launch.")
        manifest = reporting_manifest(data)
        reserved: set[int] = set()
        report_port = available_port(8091, reserved); reserved.add(report_port)
        workflow_port = available_port(8092, reserved); reserved.add(workflow_port)
        frontend_port = available_port(5173, reserved)
        token = secrets.token_urlsafe(48)
        # Pass only unrelated environment settings by default. An explicitly
        # selected Judge config forwards only its named provider credentials
        # to the Workflow API process, never to Vite or Reporting.
        common = {name: value for name, value in os.environ.items()
                  if not name.upper().endswith(("_API_KEY", "_TOKEN", "_SECRET"))}
        common["PYTHONPATH"] = str(BACKEND)
        workflow_env = common | {"SECAGENT_WORKFLOW_OPERATOR_TOKEN": token,
                                 "SECAGENT_LOCAL_SINGLE_USER": "1"}
        workflow_credential_names: set[str] = set()
        # Forward only explicitly registered Target catalog credential references
        # to the Workflow API process; strip them from common/Frontend/Reporting
        # regardless of variable naming.
        target_credential_env_names = resolve_target_credential_env_names(catalog_path, data / "targets")
        for name in target_credential_env_names:
            common.pop(name, None)
            workflow_env.pop(name, None)
            if os.environ.get(name):
                workflow_env[name] = os.environ[name]
                workflow_credential_names.add(name)
        evidence_path = None
        if args.evidence_policy:
            evidence_path = Path(args.evidence_policy).absolute()
            if not evidence_path.is_file() or evidence_path.resolve().is_relative_to(ROOT):
                raise ValueError('Evidence policy must be operator-owned and outside the repository.')
            sys.path.insert(0, str(BACKEND))
            from workflow.evidence_sources import load_evidence_policy
            evidence_settings = load_evidence_policy(evidence_path)
            # Never forward these credentials to Vite or Reporting, including
            # names which do not use the usual _TOKEN/_SECRET suffixes.
            for name in evidence_settings.credential_env.values():
                common.pop(name, None)
                workflow_env.pop(name, None)
                if os.environ.get(name):
                    workflow_env[name] = os.environ[name]
                    workflow_credential_names.add(name)
        judge_path = None
        if args.judge_config:
            judge_path = Path(args.judge_config).absolute()
            if not judge_path.is_file() or judge_path.resolve().is_relative_to(ROOT):
                raise ValueError("Judge configuration must be an operator-owned file outside the repository.")
            sys.path.insert(0, str(BACKEND))
            from testing.evaluation_config import RunnerEvaluationConfig, validate_live_pi_config
            judge_settings = RunnerEvaluationConfig.model_validate_json(judge_path.read_bytes())
            names = judge_settings.pi.credential_env
            for name in names:
                common.pop(name, None)
                workflow_env.pop(name, None)
            if all(os.environ.get(name) for name in names):
                validate_live_pi_config(judge_settings)
                workflow_env.update({name: os.environ[name] for name in names})
                workflow_credential_names.update(names)
            elif settings.get('judge_config') == args.judge_config:
                judge_path = None  # Configured reference; credential not present in this process.
                workflow_env['SECAGENT_JUDGE_SETUP_REASON'] = 'credential_missing'
            else:
                raise ValueError('Judge credential is unavailable in this process.')
        bridge_path = None
        bridge_settings = None
        if args.agent_bridge_config:
            bridge_path = Path(args.agent_bridge_config).absolute()
            if not bridge_path.is_file() or bridge_path.resolve().is_relative_to(ROOT):
                raise ValueError('Agent bridge configuration must be operator-owned and outside the repository.')
            sys.path.insert(0, str(BACKEND))
            from targets.bridges.promptfoo_http import load_config
            bridge_settings = load_config(bridge_path)
            common.pop(bridge_settings['credential_env'], None)
            if bridge_settings['credential_env'] not in workflow_credential_names:
                workflow_env.pop(bridge_settings['credential_env'], None)
        frontend_env = common | {
            "SECAGENT_LOCAL_PROXY_TOKEN": token,
            "SECAGENT_FRONTEND_PORT": str(frontend_port),
            "SECAGENT_WORKFLOW_PROXY_PORT": str(workflow_port),
            "SECAGENT_REPORTING_PROXY_PORT": str(report_port)}
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        def start(command, cwd, env):
            process = subprocess.Popen(command, cwd=cwd, env=env,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, creationflags=flags)
            processes.append(process)
        if bridge_settings is not None:
            bridge_env = common.copy()
            credential_name = bridge_settings['credential_env']
            if os.environ.get(credential_name):
                bridge_env[credential_name] = os.environ[credential_name]
            start([sys.executable, '-m', 'targets.bridges.promptfoo_http',
                   '--config', str(bridge_path), '--data-dir', str(data / 'agent-bridge')],
                  ROOT, bridge_env)
        start([sys.executable, "-m", "reporting.api", "--manifest", str(manifest),
               "--port", str(report_port)], ROOT, common)
        workflow_command = [sys.executable, "-m", "workflow.api", "--catalog", str(catalog_path),
               "--target-data-dir", str(data / "targets"), "--enable-controlled-runs",
               "--run-output-dir", str(RUNS), "--port", str(workflow_port)]
        if args.sync_credential_aliases:
            workflow_command.append("--sync-credential-aliases")
        if unified:
            workflow_command.append('--enable-unified-runtime')
        if args.enable_custom_imported_batch:
            workflow_command.append("--enable-custom-imported-batch")
        if args.enable_imported_live_local:
            workflow_command.append("--enable-imported-live-local")
        if evidence_path is not None:
            workflow_command.extend(['--evidence-policy', str(evidence_path)])
        if judge_path is not None:
            workflow_command.extend(["--enable-web-hybrid-judge", "--web-hybrid-config", str(judge_path)])
        if args.mcp_action_catalog:
            workflow_command.extend(["--mcp-action-catalog", str(Path(args.mcp_action_catalog).absolute())])
        if args.reviewed_mcp_catalog_sha256:
            workflow_command.extend(["--reviewed-mcp-catalog-sha256", args.reviewed_mcp_catalog_sha256])
        if args.dvaa_mcp_receipt_root:
            workflow_command.extend(["--dvaa-mcp-receipt-root", str(Path(args.dvaa_mcp_receipt_root).absolute())])
        start(workflow_command, ROOT, workflow_env)
        start([node, str(vite)], FRONTEND, frontend_env)
        token = ""  # The workflow/bridge child environments alone retain selected credentials.
        if bridge_settings is not None and not ready(
                f"http://127.0.0.1:{bridge_settings['port']}/health",
                lambda response: (lambda h: h.get('status') == 'ok'
                    and h.get('model') == bridge_settings['model']
                    and h.get('provider_sha256') == bridge_settings['provider_sha256'])(json.load(response))):
            raise RuntimeError('Agent bridge did not become ready.')
        if not ready(f"http://127.0.0.1:{report_port}/api/reports/health",
                     lambda response: json.load(response).get("status") == "ok"):
            raise RuntimeError("Reporting API did not become ready.")
        if not ready(f"http://127.0.0.1:{workflow_port}/api/testing/health",
                     lambda response: (lambda h: h.get("status") == "ok"
                         and h.get("operator_mode") == "local_single_user"
                         and h.get("mode") == "controlled_execution_enabled"
                         and h.get("asi01_batch_enabled") is False
                         and h.get("web_lab_batch_enabled") is False
                         and h.get("toolbot_lab_batch_enabled") is False
                         and h.get("custom_imported_batch_enabled") is (args.enable_custom_imported_batch or unified)
                         and h.get("imported_live_local_enabled") is (args.enable_imported_live_local or unified)
                         and h.get("evaluation_modes") == (["rule_only", "hybrid"] if judge_path else ["rule_only"]))(json.load(response)),
                     attempts=60):
            raise RuntimeError("Workflow API did not become ready in bounded local mode.")
        url = f"http://127.0.0.1:{frontend_port}/#targets"
        if not ready(f"http://127.0.0.1:{frontend_port}/",
                     lambda response: response.status == 200):
            raise RuntimeError("Frontend did not become ready.")
        print(f"SecAgent is ready at {url}")
        print("Press Ctrl+C here to stop only these SecAgent services.")
        if not args.no_browser:
            webbrowser.open(url)
        while all(process.poll() is None for process in processes):
            time.sleep(0.5)
        raise RuntimeError("A SecAgent service stopped unexpectedly.")
    except KeyboardInterrupt:
        print("Stopping SecAgent local services.")
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as error:
        print(f"Local startup failed: {error}", file=sys.stderr)
        return 2
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()


if __name__ == "__main__":
    raise SystemExit(main())
