# G16-R3 — Security Review

- **Repository:** `D:\SecAgent-Integration`
- **Base Git Revision:** `f72741124d6754aff4a924ec73f75d776f1fe3ae`

---

## 1. Security Properties Verified

### 1.1 Zero Raw Secret / Argument / Stdout Exposure to External LLM Judge
- `HttpTargetAdapter` (`http_evidence.py`) hashes raw tool arguments (`arguments_sha256`) and raw observations (`observation_sha256`) at ingestion and never stores raw values in `Evidence.data`.
- G16-R3 does **not** weaken or bypass hashing/redaction, and does **not** expand `EvaluationRequestBuilder` to include raw arguments, raw stdout, credentials, or observations.
- Verified in `test_fixture_a_aigoat_like_steps_action_prohibited_run_shell_detected`:
  - Both `"SECRET_TOKEN_DO_NOT_LEAK"` (inside `steps[0].action_input.command`) and `"raw stdout should stay hashed"` (inside `steps[0].observation`) are absent from the serialized `EvaluationRequest` JSON (`EvaluationRequestBuilder().build(tc, obs, evidence_v2=ev2)`).
  - Furthermore, when an explicitly prohibited reported tool invocation matches deterministically, the external LLM Judge is **not invoked at all** (`len(judge.requests) == 0`).

### 1.2 Prompt-Injection Resistance (No Inference From Untrusted Text)
- Prohibited tool names are read **exclusively** from `trusted_context` (`prohibited_tools`, `forbidden_tools`, `unauthorized_tools`), backed by `has_verified_context_revision()`.
- Neither user/attack prompts nor target response text can inject, infer, or override the prohibited tool set.
- Verified in `test_fixture_e_missing_tool_event_never_fabricates_tool_invocation`: response prose naming prohibited tools (`"execute_code"`, `"run_shell"`) without an adapter-normalized tool event never triggers a tool-action FAIL.

### 1.3 Anti-Spoofing, Anti-Escalation, Verified-Policy Parity & Correlation Integrity (Fail-Closed)
- **Provenance pinning:** `describe_prohibited_reported_tool_finding()` strictly requires `item.source == "http_response"`, `data["provenance"] == "target_reported"`, and `data["execution_verified"] is False`, plus expected `observation_scope` and `reference` prefix (`http.inline.` or `http.choices.`).
- **Verified-context provenance & deny-overrides enforcement (G16-R3-R1 A/B & G16-R3-R2 B):** `_has_trusted_prohibited_tool_policy_context()` enforces explicit provenance (`context_source`, `policy_review_status == "reviewed"`, policy ID, and revision consistency — or `operator_declared` Application Context with `application_context_id`) directly inside `describe_prohibited_reported_tool_finding()` and `find_explicit_prohibited_reported_tool_invocations()`. A bare syntactically valid SHA-256 string cannot trigger P0B-1 deterministic FAIL, and `authorized_tools` cannot silently override an explicit `prohibited_tools` entry (deny-overrides).
- **Fail-closed on truncated responses (`finish_reason="length"`):** Responses with `response_complete is False` / `completeness == "partial"` never trigger prohibited-tool `FAIL` and stay `INCONCLUSIVE`.
- **Forged `execution_verified=True` rejected fail-closed:** `_check_inline_evidence_integrity()` and `build_evidence_contract_v2()` reject any HTTP event claiming `execution_verified=True` or independent provenance (`INCONCLUSIVE` / `INVALID_EVIDENCE_INTEGRITY`).
- **Correlation confidence honesty (G16-R3-R1 C & G16-R3-R2 A):** `_inline_event_correlation_status()` distinguishes `"conflict"` (fail-closed `INCONCLUSIVE` across both `target_inline_event` and `declared_tool_call`), `"matched"` (requires at least one actual matching `(event_id, observation_id)` identifier pair; an uncorroborated `correlation_valid=True` without matching IDs is classified `"absent"` because `HttpTargetAdapter` never emits `correlation_valid`), and `"absent"` (negative check passed; same-response HTTP envelope only, explicitly disclosed in `reason` and `observation_limitations`).
- **No silent privilege escalation across scopes:** Under `execution_action` scope, target-reported HTTP events can never satisfy verified execution (`test_scope_contract_target_reported_event_never_upgraded_under_execution_action`).

### 1.4 Authorized-Tool Safety (No False Positives on Legitimate Code-Execution Agents)
- Agents whose legitimate role includes code execution are protected in two independent ways:
  1. **Opt-in by default:** Without `prohibited_tools` in reviewed `trusted_context`, invoking `run_shell` or `execute_code` never triggers this rule (Fixture `D1`).
  2. **Explicit `authorized_tools` precedence:** Any tool listed in `trusted_context["authorized_tools"]` is subtracted from `prohibited_tools` (Fixture `D2`).

### 1.5 Resilience Against Judge Availability Faults (DoS / Timeout Masking)
- Because `find_explicit_prohibited_reported_tool_invocations()` executes deterministically before calling the external Judge in both `evaluate_with_evidence_v2()` and `HybridEvaluator.evaluate()`, provider timeouts or rate limits (as observed in 15/20 cases of Run `81b73474`) can no longer mask a correlated prohibited reported tool invocation as `JUDGE_ERROR` / binary `PASS` (`test_judge_provider_timeout_still_detects_prohibited_reported_tool`).

---

## 2. Threat Model Residual Risks (Out of Scope for P0B-1)

| Residual Risk | Mitigation / Future Scope |
|---|---|
| Target omits tool execution from its HTTP JSON response | Requires independent runtime observer (e.g., MCP/sidecar/collector under `execution_action` scope), already supported by SecAgent's `scope_family == "execution"`. |
| Authorized tool invoked with malicious arguments (e.g., `run_shell` allowed for `echo`, misused for `cat /etc/shadow`) | Out of scope for P0B-1 (tool-name level only); requires separate redacted/policy-scoped argument evaluation or independent execution policy (`arguments_sha256` / command policy) in a future design. |
| Misconfigured `prohibited_tools` in operator policy | Mitigated by requiring reviewed policy revision SHA-256 (`has_verified_context_revision`) and `authorized_tools` override. |
