# Local target discovery (B4.5A)

Discovery feeds the existing Target Management form. It creates a metadata
record in the operator-owned target data directory and proposes a profile;
the existing catalog remains the authority for save, revision, review,
connection probe and execution admission. Discovery records are separate from
native security reports and have no ASI verdict.

## Operator workflow

1. Start SecAgent normally with `python start_secagent_local.py`. Open
   **Targets → Discover from URL**.
2. Enter an explicitly authorized literal loopback IP URL with a port, such
   as `http://127.0.0.1:7004/v1/chat/completions` or `http://127.0.0.1:7010/`.
   The DVAA adapter selects the MCP metadata method for ToolBot 7010; other
   MCP root URLs can use **Discovery options → MCP JSON-RPC**. Check the bounded metadata
   authorization and choose **Discover Target**. HTTP discovery makes at most
   three GET requests; MCP makes one `tools/list` POST. No chat prompt or
   `tools/call` is sent during discovery.
3. The detected endpoint, protocol, adapter and available model fill a short
   configuration form immediately. Enter a model manually when an HTTP service
   does not advertise one. Metadata, evidence candidates, compatibility hints
   and provenance remain under **Advanced Details**.
4. Confirm the exact endpoint and choose **Test Connection**. This separate
   provisional check sends one benign HTTP chat request or one MCP `tools/list`
   request. It does not save or review a target. Choose **Save Target**; the
   profile remains unreviewed. Explicitly review its current revision before
   testcase selection. A successful provisional probe can be shown for that
   exact saved revision without sending a second request.

Manual **Add Target** remains available when metadata is absent or the
protocol has no managed-target adapter.

## Discovery contract

- Accepted URL scheme: HTTP or HTTPS. Initial destination policy: literal
  loopback IPv4 or IPv6, explicit port, and one of `/`,
  `/v1/chat/completions`, `/chat/completions`, `/openapi.json`,
  `/.well-known/agent.json`, `/mcp`, or `/jsonrpc`. Hostnames and non-loopback destinations are
  deliberately rejected. This avoids DNS rebinding in the first local-only
  implementation; it is not a general internal-network discovery policy.
- At most three conventional metadata URLs are requested on the validated
  origin: `/v1/models`, `/openapi.json`, and `/.well-known/agent.json`.
  Each GET has a 3-second timeout and a 16 KiB decoded response limit.
  Redirects and proxy environment variables are disabled. Unexpected paths,
  userinfo, queries, fragments and encoded paths are rejected before connect.
- `/v1/models` can advertise model identifiers. OpenAPI can advertise the
  conventional chat POST route. A2A-style agent metadata can advertise a
  name, declared skills and explicit tool names. Skills and tools are recorded
  separately. The engine never fetches remote schema references
  or invokes declared tools. A metadata source is **advertised**, not proof
  that chat, a model, a tool or a security testcase works.
- An explicit MCP hint or `/mcp` or `/jsonrpc` path makes one bounded
  `tools/list` JSON-RPC request to the exact input URL. A matching response ID
  and tool-list shape permit an MCP profile proposal. Tool names are bounded;
  descriptions and raw response bodies are not retained. Tool invocation,
  handler execution, model identity and action provenance remain unknown.
- A trusted target adapter may choose a bounded metadata method for a known
  local endpoint. The DVAA adapter uses `tools/list` for ToolBot on port 7010;
  it still requires a valid JSON-RPC response before proposing MCP.
- Operator-supplied chat path and protocol hint are configuration claims.
  Managed profiles support OpenAI-compatible chat and reviewed loopback MCP
  JSON-RPC. OpenAPI and A2A documents are review evidence; they do not create
  OpenAPI or A2A execution adapters. An optional credential alias must
  already be registered server-side; discovery records only its name and
  sends no credential. The generic MCP profile uses a service identifier in
  the required model field; it is not a discovered LLM model.
- Target adapter providers may propose evidence source locators. DVAA's adapter
  declares dashboard attack log, command log and sandbox file endpoints for
  known local ports. These are **candidate / needs review** only. Discovery
  does not probe the dashboard, collect events, verify correlation, authorize
  the evidence source or pass a snapshot to the Judge. Use the exact source
  allowlist and manual Evidence Sources workflow to authorize collection.
- Text ASI01 binding recommendations are **CONDITIONAL** when a chat endpoint
  is identified, and **UNKNOWN** otherwise. Other native cases are
  **UNSUPPORTED** because no reviewed execution binding follows from
  metadata. Discovery never returns **SUPPORTED** solely from metadata.
  Backend preview and admission remain authoritative. Planning states are
  separate from security PASS/FAIL/INCONCLUSIVE.

## Storage and safety

The authenticated Workflow API writes one atomic JSON record under the
operator-owned `discoveries` directory. It contains discovery ID, time,
canonical URL, source URLs and statuses, sanitized advertisements, unknown
fields, warnings, and any associated saved profile revision. It stores no
raw metadata bodies, credential values, headers or security-test evidence.
Saving a suggested profile requires the same candidate endpoint and protocol;
it does not mark the profile reviewed. Changing either in the quick-connect
form clears connection status and requires a new discovery before probe or
save. **Add Target** remains available as the separate manual path.

The operator-authorized `POST /api/testing/discovery-probes` validates the
unsaved profile and its discovery binding, then reuses Target Management's
single-request bounded connection probe. It does not write a profile, target
review, execution grant or security verdict. Changing the URL or configuration
clears the displayed connection status.

The local proxy admits only exact discovery routes and adds the internal
operator credential. The Workflow API independently checks loopback host,
origin, validation nonce and operator authentication. A broader destination
policy, DNS pinning for reviewed hostnames, authenticated metadata retrieval,
custom protocol adapters and real target action verification require separate
review. The 2026-11-19 MVP live checks and their limits are recorded in
`docs/audits/secagent_auto_discovery_mvp.md`.
