"""Explicitly authorized lab HTTP profiles; no discovery occurs by default."""

import ipaddress
import re
from urllib.parse import urlsplit

from core.models import TargetProfile
from tools.http import HttpClient, HttpClientError


class RuntimeTargetError(ValueError):
    """Invalid runtime target (messages never include supplied URL secrets)."""


def _url(value: str):
    try:
        parsed = urlsplit(value)
        port = parsed.port
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or port == 0 or parsed.query or parsed.fragment or "\\" in value
                or any(c.isspace() or ord(c) < 32 for c in value)):
            raise ValueError
        host = parsed.hostname.lower()
        if host != "localhost":
            address = ipaddress.ip_address(host)
            if (not (address.is_private or address.is_loopback)
                    or address.is_link_local or address.is_multicast
                    or address.is_unspecified or (address.is_reserved and not address.is_loopback)):
                raise ValueError
        origin = (parsed.scheme, host, port or (443 if parsed.scheme == "https" else 80))
        return parsed, origin
    except ValueError:
        raise RuntimeTargetError("Use an HTTP(S) lab IP or localhost URL without credentials, query or fragment.") from None


def build_runtime_target(
    url: str, target_id: str, *, protocol: str = "openai-chat",
    authorized_origin: str, model: str = "default", credential_env: str | None = None,
    discover: bool = False, http_client: HttpClient | None = None,
) -> TargetProfile:
    """Build a profile without persisting credentials or trusting health claims.

    URL is the complete chat endpoint. Authorization is an exact origin, not a
    wildcard. Literal private IPs avoid DNS rebinding of arbitrary lab names.
    """
    if protocol != "openai-chat":
        raise RuntimeTargetError("Unsupported target protocol; supported: openai-chat.")
    parsed, origin = _url(url)
    allowed, allowed_origin = _url(authorized_origin)
    if allowed.path not in {"", "/"} or origin != allowed_origin:
        raise RuntimeTargetError("Target URL must match the explicitly authorized lab origin.")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", target_id):
        raise RuntimeTargetError("Target identifier must be a simple identifier.")
    if not model.strip() or any(ord(c) < 32 for c in model):
        raise RuntimeTargetError("Target model must be non-empty without control characters.")
    headers = {"Content-Type": "application/json"}
    if credential_env:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", credential_env):
            raise RuntimeTargetError("Credential reference must be an environment variable name.")
        # Existing adapter supports whole-header credential placeholders.
        headers["Authorization"] = "{{credential:" + credential_env + "}}"
    metadata = {"configuration_source": "runtime", "protocol": protocol}
    if discover:
        metadata["health_discovery"] = "unavailable"
        try:
            response = (http_client or HttpClient(trust_env=False)).request(
                method="GET", url=f"{parsed.scheme}://{parsed.netloc}/health", timeout=3,
            )
            if response.status_code == 200 and isinstance(response.json_body, dict):
                # Health text is untrusted advisory data, never an identity override.
                identity = response.json_body.get("id") or response.json_body.get("agent")
                if isinstance(identity, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", identity):
                    metadata["health_reported_identity_untrusted"] = identity
                metadata["health_discovery"] = "available"
        except HttpClientError:
            pass
    return TargetProfile(id=target_id, name=target_id, target_type="ai_agent",
        interface={"type": "http", "adapter": "generic_http", "config": {
            "url": url, "method": "POST", "headers": headers, "trust_env": False,
            "body": {"model": model, "messages": [{"role": "user", "content": "{{input}}"}]},
            "response": {"text_path": "choices.0.message.content"},
        }}, capabilities=["chat"], observability=["response"],
        credential_refs=[credential_env] if credential_env else [], metadata=metadata)
