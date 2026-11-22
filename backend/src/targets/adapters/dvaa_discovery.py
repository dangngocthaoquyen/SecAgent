"""DVAA lab evidence suggestions; never probes or authorizes a source.

The dashboard telemetry endpoints are target-owned snapshots. A port match is
only an adapter hint, not proof that the service is DVAA or that an action ran.
"""

from urllib.parse import urlsplit


class DvaaEvidenceDiscoveryProvider:
    _ports = {7004: "openai-chat", 7010: "mcp-jsonrpc"}
    _sources = (
        ("DVAA Attack Log", "/api/attack-log", "attack_log", "request_identity_not_guaranteed"),
        ("DVAA Sandbox Command Log", "/api/sandbox/cmd-log", "command_log", "request_identity_not_guaranteed"),
        ("DVAA Sandbox Files", "/api/sandbox/files", "sandbox_file_snapshot", "no_per_request_correlation"),
    )

    def preferred_protocol(self, *, origin: str, input_path: str) -> str | None:
        """A port hint selects a safe metadata probe, never a capability claim."""
        parts = urlsplit(origin)
        if parts.hostname in {"127.0.0.1", "::1"} and parts.port == 7010 and input_path == "/":
            return "mcp-jsonrpc"
        return None

    def candidates(self, *, origin: str, endpoint: str | None, protocol: str,
                   connection_status: str, tools: tuple[str, ...], models: tuple[str, ...]) -> list[dict]:
        parts = urlsplit(origin)
        if (connection_status != "reachable" or endpoint is None or
                self._ports.get(parts.port) != protocol or parts.hostname not in {"127.0.0.1", "::1"}):
            return []
        dashboard_host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
        dashboard = f"{parts.scheme}://{dashboard_host}:9000"
        return [{"source_name": name, "url": dashboard + path,
                 "evidence_type": kind, "discovery_provenance": "dvaa_adapter_known_endpoint",
                 "availability": "candidate_needs_review", "verification_status": "not_verified",
                 "correlation_capability": correlation,
                 "required_authorization": "operator_review_and_exact_evidence_allowlist",
                 "limitations": "Dashboard endpoint and DVAA identity are not probed; target-owned telemetry cannot prove independent execution."}
                for name, path, kind, correlation in self._sources]
