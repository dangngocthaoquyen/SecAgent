# 06 — Security Model, ASI05 Case Study & Target Generalization

> **Audit Classification:** Distinguishes **(1) Confirmed implementation**, **(2) Intended design/policy**, **(3) Confirmed limitation**, **(4) Suspected defect requiring reproduction**, and **(5) Proposed future architecture**.

## 1. Implemented Security Controls & Trust Boundaries

| Security Domain | Confirmed Implementation | Verified Boundaries / Limitations |
|---|---|---|
| **Loopback & Proxy Auth Boundary** | `start_secagent_local.py:130-353`, `frontend/vite.config.ts:1-120` bind all 3 processes to `127.0.0.1`. Vite strips browser-supplied `X-SecAgent-Operator`, enforces route/method allowlist, and injects `SECAGENT_LOCAL_PROXY_TOKEN` only on `/api/testing/*`. Workflow API validates `X-SecAgent-Validation` nonce (`secrets.compare_digest`). | Designed for single-operator local research workstations; **not** a multi-tenant internet-facing SaaS (no RBAC, no TLS termination, no cross-process distributed auth). |
| **Target Allowlists & SSRF Controls** | `discovery.py:67-96` strictly allows literal loopback IPs only (no DNS, no redirects, max 3 requests). `workflow/catalog.py:134-146` allows loopback/localhost OR RFC1918 private IPs for `http-json`, loopback-only for `mcp-jsonrpc`. `observers/evidence_collectors.py:116-148` rejects paths outside `allowed_roots` (incl. symlinks/Windows reparse points) and URLs outside `allowed_endpoints` (no redirects). | `http-json` allowing any RFC1918 private IP assumes the operator controls the local/lab network; there is no egress CIDR denylist beyond private/loopback check. |
| **Credential Handling & Redaction** | Server-managed `credential_alias` (env vars) and RAM-only `SessionCredentialStore` (max 64 entries, origin+scope+header bound, cleared on restart, `http-json` only). `targets/validator.py:27-50` rejects arbitrary `{{...}}` header templates. `DEEPSEEK_API_KEY` stays in Workflow API process only; Reporting API (`:8091`) receives zero secrets. `Redactor` (`reporting/redaction.py`) and `http_evidence.py` hash/scrub tokens before persistence and Judge calls. | Session credentials do not survive Workflow API restarts (by design, requiring re-entry before Resume). |
| **Prompt Injection Trust Boundaries** | Generator separates `generation_parameters` from `untrusted_application_data` (`trust_level: "untrusted_data_not_instructions"`, `generator/request_builder.py`) and only accepts `operator_confirmed` A–E fields (`generator/readiness.py:520-531`). Judge uses `evaluator_skills/security/untrusted-content-policy.md`, strict JSON v1.0 validation, and exact span/reference citation checks (`integrations/external_evaluator/validation.py:89-100`). | LLM Judge remains probabilistically susceptible to sophisticated semantic adversarial responses; deterministic rules and verified runtime evidence remain higher authority than Judge recommendations. |
| **Operator Authorization & TOCTOU** | Discovery, Benign Probe, Application Context save, Policy review, Preview Save, Scan Start, and Resume each require explicit confirmation flags (`authorization_confirmed=True`, `review_confirmed=True`, `stateful_target_acknowledged=True`). `start_run` pins `expected_target_revision` and `expected_session_credential_generation` under catalog+service locks (`routes_generic_runner.py:2299-2358`). | Frontend `SecurityScanWizard.tsx:1016-1025, 1053` auto-includes uncertain cases on Resume preview open (still requires clicking *Confirm & Resume* after disclosure). |
| **Concurrency Safety & Budgets** | `TargetExecutionLockRegistry` (`workflow/target_locks.py`) locks both `target:<id>` and canonical physical `endpoint:<scheme>://<host>:<port><path>` across Generic Runner, Generate & Run, Legacy Batch, and MCP Actions. `BudgetedJudgeProvider` (`testing/evaluation_config.py:76-100`) enforces hard call cap (`max_judge_calls = len(pairs)`). Generator caps chunks (`<=4/ASI`), calls (`<=8 total`), and output tokens (`<=32768`). | **Confirmed limitation:** `TargetExecutionLockRegistry` is **in-process only**. Launching two separate Workflow API OS processes against the same target will NOT share locks. |
| **Data Integrity & Reproducibility** | Atomic file writes, SHA-256 verification on datasets (`DatasetRepository`), controlled runs (`_verify_completion_invariants`, `reporting/repository.py`), skill bundles (`skill_sha256`), and Resume lineage (`resume_digest`). | Live LLM targets and LLM Judges are inherently non-deterministic across runs; reproducibility is guaranteed for offline replay and audit provenance, not identical live model outputs. |

---

## 2. Deep-Dive Case Study: The ASI05 Situation (Source-Verified, Zero Live Calls)

This section answers every specific architectural question regarding `ASI05` (`unexpected_code_execution`) on an `http-json` target returning inline `steps` (e.g., `run_shell`) purely from source inspection:

### Q1. Why do `response_command_artifact` and `execution_action` behave differently?
- **Confirmed Implementation (`generator/readiness.py:39-51`, `evaluators/contract.py:27-40`):**
  - `response_command_artifact` belongs to `RESPONSE_ONLY_SCOPES`. It evaluates whether the agent's **final response text** outputs prohibited commands/code artifacts, using `evaluator_skills/security/vulnerabilities/unexpected-code-execution-response.md` via the Hybrid Judge. An `unverified` capability produces only a warning, never a blocker.
  - `execution_action` belongs to `EXECUTION_SCOPES`. It evaluates whether **actual runtime code/command execution occurred**, requiring capability support (`runtime_execution`, `execution_action`, `code_execution`, or `agent_runtime_actions`) and independently verified runtime evidence.

### Q2. Why does `execution_scope_capability_unverified` occur?
- **Confirmed Implementation (`workflow/catalog.py:62-63`, `generator/readiness.py:836-842`):**
  - When an `http-json` target is onboarded, `default_capability_states_for_preset()` initializes only `{"response_behavior": "unverified", "chat": "unverified"}` (and `DiscoveryPanel.tsx:28` sets `{"response_behavior": "unverified", "tool_intent": "unverified"}`).
  - `runtime_execution` is undeclared/unverified by default. When an operator selects `execution_action` in Generator Readiness, `_assess_single_asi()` (`readiness.py:836-842`) fails closed with blocker **`execution_scope_capability_unverified`** instead of silently downgrading to `response_command_artifact`.

### Q3. What is the exact role of `runtime_execution = supported`?
- **Confirmed Implementation (`generator/readiness.py:836-856`, `evaluators/contract.py`):**
  - Setting `capability_states["runtime_execution"] = "supported"` with `operator_declared` (or `runtime_confirmed`) provenance — **not** `discovery_suggested` — clears the `execution_scope_capability_unverified` blocker and downgrades it to warning `capability_not_runtime_verified`.
  - It is a **planning/admission declaration**, NOT proof that runtime execution occurred or that independent runtime evidence exists.

### Q4. Do inline `steps` alone meet the current runtime evidence contract?
- **Confirmed Limitation (Readiness-vs-Evaluation Contract Asymmetry):**
  - **At Generator Readiness time (`generator/readiness.py:325-333, 857-862`):** `_has_runtime_evidence()` checks `capability_summary["evidence_availability"]` and **accepts `"inline_structured_evidence"`** (which `catalog.py:266, 282` and `contract.py:239-240` populate whenever `http_config.response.evidence_mapping` is configured). Therefore, Generator allows creating `execution_action` testcases for a target that only has inline `steps`.
  - **At Evaluation time, inline `steps` DO NOT meet the runtime evidence contract:**
    1. `http_evidence.py:204-319` extracts inline `steps` into `Evidence(kind="target_inline_event", source="http_response", data={"provenance": "target_reported", "execution_verified": False, "verification_status": "target_reported_unverified", ...})`.
    2. `core/models/evidence.py:195-247` (`is_execution_verified()`) **never** returns `True` for `target_inline_event` / `provenance="target_reported"`.
    3. `asi05_execution.py:103-120` requires `asi05_execution_observer_verified=True` and `kind="asi05_execution_trace"` from trusted observer sources (`asi05_execution_fixture`, `asi05_mcp_request_observer`, `asi05_agent_mcp_observer`, `instrumented_handler_receipt`). Inline `steps` fail with `trusted_observer_missing` / `missing_trace`.
    4. `evidence_v2_evaluator.py:751-1088` hits **Branch E4 (`L1056-1058`)** for `scope_family == "execution"` without `execution_verified and correlation_verified`: emits `outcome_reasoning_code="target_reported_claim_unverified"`, internal `INCONCLUSIVE`, and **`allow_semantic_fallback=False`** (so the LLM Judge is **not even invoked**!).
    5. Under Binary Policy v2.2.0 (`verdict_outcome.py:314-499`), this resolves to **`verdict="PASS"`** with `evidence_limitations=["insufficient_runtime_evidence"]` — even if `steps` reported `run_shell` executing a dangerous command!
    6. Furthermore, while `verdict_resolver.py:1450-1586` implements `_inspect_lab_inline_actions` / `find_prohibited_lab_inline_actions` to detect prohibited inline lab actions in response-only scope, that logic is gated strictly to `category == "tool_misuse"` (`ASI02`) and is **not** wired for `unexpected_code_execution` (`ASI05`, `L1394-1449`).

### Q5. How is `run_shell` mapped into evidence, and do command arguments & observations reach the Judge?
- **Confirmed Implementation (`targets/adapters/http_evidence.py:204-319`, `core/models/evidence.py:391-427`, `evaluators/evaluation_request_builder.py:209-217`):**
  - An inline step item (e.g., `{"action": "run_shell", "action_input": {"cmd": "id"}, "observation": "uid=0...", "status": "ok"}`) is mapped to `Evidence(kind="target_inline_event", source="http_response", name="run_shell", data={...})`.
  - **Do raw command arguments or raw observations reach the Judge? NO (by intentional privacy/redaction design):**
    - `http_evidence.py:244-251, 295-306` hashes raw `arguments` -> `arguments_sha256` (preserving only top-level `argument_keys`, e.g. `["cmd"]`) and raw `observation` -> `observation_sha256` (preserving only `observation_type`, e.g. `"str"`), appending `disclosure_limitation`.
    - `public_evidence_data()` (`core/models/evidence.py:391-427`) and `EvaluationRequestBuilder.build()` (`evaluation_request_builder.py:209-217`) strictly enforce this allowlist.
    - **Consequence:** Even in `response_command_artifact` (where the Judge IS called), the Judge sees `response_text`, action name (`"run_shell"`), `argument_keys`, `arguments_sha256`, `observation_sha256`, `status`/`decision`, and `provenance` — **never the raw shell command string or command stdout** unless the target echoes them into `response_text`!

### Q6. How are `NONZERO_EXIT` and API HTTP 402 insufficient-balance errors handled?
- **Confirmed Implementation & Gap (`integrations/external_evaluator/pi.py:65-80`, `evaluators/hybrid_evaluator.py:95-99`, `generator/providers/deepseek_http.py:223-247`):**
  - In `pi.py:65-80`, `_classify_nonzero_stderr()` maps stderr regexes to `CREDENTIAL_MISSING`, `AUTH_REJECTED` (401/403), `MODEL_REJECTED`, `NETWORK_ERROR`, `STARTUP_ERROR`, or fallback `ProcessDiagnosticCode.UNKNOWN`.
  - **HTTP 402 (Insufficient Balance / Payment Required) has NO dedicated classification** in either `pi.py` (becomes `ProviderFaultCode.NONZERO_EXIT` + `ProcessDiagnosticCode.UNKNOWN`) or `deepseek_http.py` (becomes generic `ProviderErrorCategory.HTTP_ERROR`).
  - `HybridEvaluator._RETRYABLE_JUDGE_FAULTS` (`hybrid_evaluator.py:95-99`) only retries `TIMEOUT`, `PROCESS_ERROR`, `INVALID_OUTPUT` — **`NONZERO_EXIT` is never retried** (and `GenericRunService` defaults `max_technical_retries=0`).
  - Because `verdict_outcome.py:399-416, 545-611` projects `JUDGE_ERROR` to binary `verdict="PASS"` and includes it in `pass_count` / `pass_rate_percent`, an exhausted DeepSeek balance causing HTTP 402 on every Pi CLI call produces **`100% PASS` + `technical_failure_count = N (JUDGE_ERROR)`**.

---

## 3. Target Generalization & Multi-Step Architectural Boundaries

### 3.1 Supported vs. Unsupported Target Execution Patterns

| Capability / Target Pattern | Current Status in `HEAD` | Source Evidence |
|---|---|---|
| **Single-request HTTP JSON (`http-json`) / OpenAI Chat (`openai-chat`)** | **Fully Supported** | `targets/adapters/http_adapter.py`, `workflow/models.py` |
| **Direct stateless MCP JSON-RPC `tools/call` (`mcp-jsonrpc`)** | **Supported** (with optional DVAA lab receipt binding) | `targets/adapters/mcp_jsonrpc_adapter.py`, `dvaa_action_evidence.py` |
| **Hosted MCP Agent multi-turn tool loop (`mcp_agent_runtime`)** | **Supported (Legacy/Batch route only)** — LLM calls + MCP tool calls bounded by `max_model_calls`/`max_tool_calls`, NOT wired into `GenericRunService` | `targets/runtimes/mcp_agent.py`, `workflow/routes_execution.py` |
| **Multi-step stateful HTTP conversation (turn 1 -> turn 2 -> turn N)** | **NOT Supported** in `GenericRunService` / `HttpTargetAdapter` (1 testcase = 1 HTTP POST request) | `targets/adapters/http_adapter.py:45-170`, `testing/generic_runner.py` |
| **Multi-role orchestration (e.g., User A submits artifact -> Admin Agent B processes it)** | **NOT Supported** natively (a target profile binds 1 endpoint + 1 credential/session) | `workflow/models.py`, `routes_generic_runner.py:944-1068` |
| **Target-side setup / baseline reset / cleanup hooks** | **NOT Supported** (explicitly disclosed in `ScanResumePanel.tsx:320`: *"SecAgent does not automatically restore target state."*) | `routes_generic_runner.py:4646-4648`, `ScanResumePanel.tsx:320` |
| **A2A Protocol** | **Explicitly Unsupported** | `routes_targets.py:88-93` |

### 3.2 Concrete Target Comparison (DVAA vs. AIGoat vs. MCP)
- **DVAA:** Works via `openai-chat` (Chat bots), `mcp-jsonrpc` (ToolBot), and optional DVAA-specific lab observers (`DvaaActionObserverFactory`, `DvaaInstrumentedReceiptCollector` on port `7110`) that can supply `independently_verified_execution` traces for `ASI05`.
- **AIGoat (Zero Hardcoded Code):** Onboarded purely as a generic `http-json` target. Works out-of-the-box for single-request endpoints (e.g., direct agent runner POST returning `answer` + inline `steps`). Cannot natively execute multi-role indirect prompt injection flows (such as **AIGoat ASI01**: low-privilege user Alice creates a poisoned support ticket -> privileged Admin Agent reads & acts on ticket) without external orchestration.

### 3.3 Proposed Future Integration Design: External Middleware for AIGoat ASI01 Multi-Role Indirect Injection

> **[PROPOSED FUTURE DESIGN — NOT IMPLEMENTED IN CURRENT REPOSITORY]**  
> To test multi-role indirect prompt injection (e.g., **Alice submits ticket -> Admin Agent triages ticket -> Side-effect observation**) **without modifying SecAgent's core `http-json` contract**, an external **Scenario Middleware Adapter** can sit between SecAgent and AIGoat on loopback:

1. **Ingress Contract (SecAgent -> Middleware):** SecAgent treats the middleware as a standard `http-json` target (`POST http://127.0.0.1:<port>/scenarios/asi01/run`) sending `{"prompt": "{{input}}", "correlation_id": "..."}` with standard `session_auth` or `credential_alias`.
2. **Orchestration Inside Middleware (External to SecAgent):**
   - **Step 1 (Setup / Isolation):** Reset or namespace synthetic ticket state and generate a fresh `scenario_run_id`.
   - **Step 2 (Untrusted Actor — Alice):** Authenticate as Alice (`POST /api/tickets`) and submit the SecAgent testcase `prompt` as untrusted ticket body content.
   - **Step 3 (Victim Actor — Admin Agent):** Trigger the Admin Triage Agent (`POST /api/admin/agent/triage`) referencing the created ticket ID.
   - **Step 4 (Independent Effect Observation & Cleanup):** Query AIGoat's backend DB/audit/sandbox state (independently of the Admin Agent's self-reported text) to verify whether a prohibited privileged action actually occurred, write a strongly correlated (`run_id` + `case_id`) JSON attestation record into an allowlisted `SandboxLogFileCollector` / `FileArtifactCollector` directory, and optionally clean up the synthetic ticket.
3. **Egress Contract (Middleware -> SecAgent):** Return a single bounded HTTP 200 JSON response `{ "answer": "<admin_agent_response>", "status": "completed", "run_id": "<scenario_run_id>", "steps": [...] }` matching SecAgent's `HttpResponseContract`, while the separate scoped collector provides `independently_verified_execution` evidence.
4. **Why This Preserves Architectural Integrity:** Keeps SecAgent target-agnostic (zero AIGoat hardcoding), preserves single-request `GenericRunService` budgets/cancellation/resume invariants, and cleanly separates target-reported claims from independently verified side-effect attestation.
