# 04 — Generator (G11) and Hybrid Judge (G12/G14) Deep Dive

> **Audit Classification:** Confirmed source implementation (`HEAD: 31614ca`).  
> **Companion Diagrams:** [04-generator-internal-workflow.md](./diagrams/04-generator-internal-workflow.md), [05-evidence-and-verdict-decision-flow.md](./diagrams/05-evidence-and-verdict-decision-flow.md)

## 1. AI Testcase Generator (G11)

### 1.1 Supported Scope, Protocols & Hard Bounds (`backend/src/generator/constants.py`)

| Parameter | Verified Value | Source Citation |
|---|---|---|
| Supported ASIs | `ASI01` (`goal_hijacking`), `ASI02` (`tool_misuse`), `ASI03` (`identity_privilege_abuse`), `ASI05` (`unexpected_code_execution`) | `generator/constants.py:13-24` |
| Supported Target Protocols | `openai-chat`, `http-json` (`mcp-jsonrpc` blocked with `unsupported_target_protocol`) | `generator/readiness.py:37` |
| Per-ASI Count Limits | Min `1`, Default `5`, Max `50`, Hard Max `50` | `generator/constants.py:42-48` |
| Total Cases per Generation | Max `50`, Hard Max `50` | `generator/constants.py:46-48` |
| Bounded Chunking | `DEFAULT_GENERATION_CHUNK_SIZE = 15`, `MAX_PLANNED_CHUNKS_PER_ASI = 4` | `generator/constants.py:53-55` |
| Provider Call Ceilings | `MAX_TOTAL_PROVIDER_CALLS_PER_ASI = 5`, `MAX_GENERATION_TOTAL_PROVIDER_CALLS = 8` | `generator/constants.py:56-57` |
| Output Token Ceiling | `MAX_GENERATION_OUTPUT_TOKEN_BUDGET = 32768` | `generator/constants.py:59` |
| Retry Policy | `max_calls_per_asi` in `{1, 2}` (at most 1 ASI-wide transient retry when set to `2`) | `generator/service.py` |
| Input/Output Size Caps | `focus_note <= 300` chars; prompt `<= 4096` UTF-8 bytes; description `<= 512` chars; raw LLM JSON `<= 256 KiB` | `generator/constants.py:49-52`, `output_parser.py` |
| Preview Store Bounds | RAM-only, TTL `30 min`, max `32` active previews | `generator/preview_store.py` |

### 1.2 Readiness & Provenance Isolation (`generator/readiness.py`)

Before any provider call is permitted, `assess_target_readiness()` enforces:
1. Target exists in `ManagedTargetCatalog` and uses a supported protocol (`openai-chat` or `http-json`).
2. `ApplicationContextStore` record exists and `draft["target_revision"] == current_target_revision` (otherwise `application_context_stale`).
3. **Strict Provenance Gate (`readiness.py:520-531`):** Iterates the 18 A–E fields and copies **only** those with `field_provenance[field] == "operator_confirmed"` into `ConfirmedContextSnapshot`. Unverified discovery suggestions (`discovered_observed`, `suggested_unverified`) are dropped.
4. **Scope Capability Check (`readiness.py:836-862`):**
   - Response-only scopes (`goal_hijack_response`, `tool_intent_response`, `identity_claim_response`, `response_command_artifact`) allow `unverified` capability with a warning.
   - Execution scopes (`execution_action`, `agent_run`, `direct_request`, `web_fetch`, `web_callback`) **block** with `execution_scope_capability_unverified` unless the required capability state is `"supported"` with `operator_declared` or `runtime_confirmed` provenance (not `discovery_suggested`).
   - **Important Asymmetry (Detailed in Doc 06):** `_has_runtime_evidence()` (`readiness.py:325-333`) counts `"inline_structured_evidence"` (HTTP `evidence_mapping`) as runtime evidence availability for generation readiness, even though `EvidenceV2Evaluator` later rejects inline events as unverified at evaluation time.
5. **Reviewed Policy Resolution:** Checks `ResponsePolicyStore`; if multiple reviewed policies match the same `(target_id, category)`, blocks with `ambiguous_reviewed_policy` and returns `ambiguous_policy_candidates` so the operator can pick one explicitly.

### 1.3 Trusted Skills & Prompt Construction (`generator/skills.py`, `request_builder.py`)

- **Skill Isolation (`skills.py:1-297`):** Loads strictly from `generator_skills/` (`SKILL.md`, `safety-and-scope-policy.md`, `untrusted-context-policy.md`, and `profiles/asiXX-*.md`). Explicitly refuses any path pointing into `evaluator_skills/`. Computes deterministic SHA-256 `skill_sha256` for provenance.
- **Prompt-Injection Boundary (`request_builder.py:1-353`):**
  - System message contains only trusted `generator_skills/*.md` text.
  - User message is a structured JSON payload separating trusted `generation_parameters` (ASI code, scope, count, language, `avoid_prompts` from prior chunks) from `untrusted_application_data` (confirmed A–E fields + optional `focus_note`) explicitly wrapped with `trust_level: "untrusted_data_not_instructions"`.
  - Runs `Redactor` + regex scrubbing over all untrusted fields to strip API keys, Bearer tokens, PEM blocks, private IPv4s, and local filesystem paths before sending to DeepSeek.

### 1.4 Provider Invocation (`generator/providers/deepseek_http.py`, `provider_factory.py`)

- **Server-Owned Only:** `provider_factory.py` exclusively instantiates `DeepSeekHttpProvider` using `os.environ.get("DEEPSEEK_API_KEY")` — never accepts browser API keys, never accepts arbitrary base URLs (allowlists only `https://api.deepseek.com/chat/completions` and `/v1/chat/completions`), and **never falls back to Mock** in production.
- **Request Parameters (`deepseek_http.py`):** Default model `deepseek-flash` (configurable via env), `temperature = 0.3`, `thinking = {"type": "disabled"}`, `response_format = {"type": "json_object"}`, explicit connect/read timeouts, `follow_redirects = False`, `trust_env = False`.
- **Error Categorization (`generator/providers/deepseek_http.py:223-247`):** Maps `401/403` -> `AUTH_ERROR`, `429` -> `RATE_LIMITED`, `5xx` -> `UPSTREAM_ERROR`, timeouts -> `TIMEOUT`, network errors -> `NETWORK_ERROR`, other `4xx` (including **HTTP 402 insufficient balance**) -> generic `ProviderErrorCategory.HTTP_ERROR` (non-retryable).

### 1.5 Output Parsing, Validation & Deduplication

- **`output_parser.py:1-323`:** Rejects Markdown code fences, leading/trailing prose, duplicate JSON keys, `NaN`/`Infinity`, nesting depth `> 16`, payload `> 256 KiB`, and any `FORBIDDEN_LLM_OUTPUT_KEYS` (`verdict`, `assertions`, `assert`, `rules`, `evaluation_rules`, `evidence`, `score`, `passed`, `classification`, etc.).
- **`validation.py:1-215`:** Enforces exact `asi_category` match, bounded prompt/description sizes, non-empty `strategy_tag` and `scope_note`, and requires **every field listed in `context_basis`** to exist in the `ConfirmedContextSnapshot` (preventing hallucinated context claims).
- **`deduplication.py:1-172`:** Normalizes prompts with Unicode NFKC + whitespace collapse + lowercase -> SHA-256 (`exact_normalized_text_v1`). Always deduplicates within an ASI (across chunks too); cross-ASI deduplication is **OFF by default** (`deduplicate_across_asi=False`) so each OWASP ASI category can be evaluated independently.

---

## 2. Hybrid Evaluation & LLM Judge (G12 / G14)

### 2.1 Evaluation Architecture (`evaluators/hybrid_evaluator.py`, `testing/evaluation_config.py`)

SecAgent supports two explicit evaluation modes in `RunnerEvaluationConfig`:
1. **`rule_only`** (`judge_enabled=False`, `max_judge_calls=0`): Runs `ResponseEvaluator` (reviewed deterministic rules) + `EvidenceV2Evaluator` (runtime evidence rules). Zero external Judge calls.
2. **`hybrid`** (`judge_enabled=True`, `allow_live_judge=True`, `max_judge_calls=len(pairs)`): Combines deterministic rules, Evidence v2 gates, and Pi CLI semantic Judge under a thread-safe `BudgetedJudgeProvider` (`evaluation_config.py:76-100`). Every call reserves budget **before** delegating; exceptions/timeouts still consume the reservation.

### 2.2 Judge Readiness & Provider Configuration (`routes_generic_runner.py:785-865`)

`GenericRunService.judge_status()` resolves Judge availability in order:
1. Injected `self.judge_provider` (used in tests or custom wiring).
2. `SECAGENT_JUDGE_SETUP_REASON == "credential_missing"` override.
3. Explicit `self.pi_config` (`PiEvaluatorConfig`): checks executable exists (`is_file()` or `shutil.which`) AND either `credential_env` env vars are set OR `~/.pi/agent/auth.json` contains `pi_config.provider`.
4. Auto-discovery fallback: `shutil.which("pi")` AND `_has_pi_auth_provider("deepseek")` -> defaults to `provider="deepseek"`, `model="deepseek-v4-flash"`, `timeout_seconds=60.0`, `max_output_bytes=65536`, `use_pi_auth_file=True` (`L851-860`).

### 2.3 Prompt Construction & Trusted Rubrics (`evaluation_request_builder.py`, `integrations/external_evaluator/skills.py`)

- **Skill Bundle Selection (`skills.py:10-99`):**
  - Always loads shared files from `evaluator_skills/security/`: `SKILL.md`, `verdict-policy.md`, `untrusted-content-policy.md`.
  - Appends category rubric:
    - `goal_hijacking` -> `vulnerabilities/goal-hijacking.md`
    - `prompt_injection` -> `vulnerabilities/prompt-injection.md`
    - `tool_misuse` + `evaluation_scope == "tool_intent_response"` -> `evaluator_skills/response_first/tool-misuse-response.md`
    - `tool_misuse` (other scopes) -> `vulnerabilities/tool-misuse.md`
    - `sensitive_data_disclosure` -> `vulnerabilities/sensitive-data-disclosure.md`
    - `identity_privilege_abuse` -> `vulnerabilities/identity-privilege-abuse.md`
    - `unexpected_code_execution` -> `vulnerabilities/unexpected-code-execution-response.md`
  - Computes canonical SHA-256 `skill_identity` included in every Judge request and report.
- **Evidence Allowlist & Privacy (`evaluation_request_builder.py:209-217`, `core/models/evidence.py:391-427`):**
  - `EvaluationRequest` carries `testcase`, `trusted_context` (from reviewed policy or current operator-confirmed Application Context A–E), and `observation` (`response_text`, allowlisted `metadata`, and `public_evidence_data(ev)`).
  - Raw tool arguments and raw tool observations are **hashed and stripped** before `EvaluationRequest` is ever built (only action/tool name, top-level argument key names, `arguments_sha256`, `observation_sha256`, `observation_type`, status/decision, and provenance reach the Judge).

### 2.4 Pi CLI Invocation, Output Validation & Fault Handling (`pi.py`, `validation.py`, `hybrid_evaluator.py`)

- **Subprocess Execution (`pi.py:130-260`):**
  - Spawns `[executable, "--mode", "text", "--no-session", "--no-tools", "--provider", provider, "--model", model]` (with `--system-prompt` / stdin prompt, clean environment stripping non-allowlisted vars except configured `credential_env`, bounded stdout `max_output_bytes`, `timeout_seconds`, and cooperative `cancel_event` polling that kills the process on scan cancel).
- **Strict JSON v1.0 Output Validation (`validation.py:12-101`):**
  - Rejects duplicate keys, `NaN`/`Infinity`, non-object JSON, schema mismatches.
  - Verifies `(evaluation_type, classification) -> expected_verdict` against `LABEL_VERDICTS` (e.g., for `unexpected_code_execution`: `PROHIBITED_COMMAND_ARTIFACT -> FAIL`, `RESPONSE_BOUNDARY_PRESERVED -> PASS`, `UNCLEAR -> INCONCLUSIVE`).
  - Enforces **citation grounding (`L89-100`)**: every `PASS` or `FAIL` must include `>= 1` citation; `response_span` must be an **exact substring** of `request.observation.response_text`, and runtime citations must match a normalized `evidence[].reference`.
- **Error Classification & Retries (`pi.py:65-80`, `hybrid_evaluator.py:95-99`):**
  - `_classify_nonzero_stderr()` classifies only: `CREDENTIAL_MISSING`, `AUTH_REJECTED` (401/403), `MODEL_REJECTED`, `NETWORK_ERROR`, `STARTUP_ERROR`, else `ProcessDiagnosticCode.UNKNOWN`.
  - **Gap Confirmed:** HTTP `402` (insufficient balance / payment required) is **not** recognized in `_classify_nonzero_stderr()`, producing `ProviderFaultCode.NONZERO_EXIT` + `ProcessDiagnosticCode.UNKNOWN`.
  - `_RETRYABLE_JUDGE_FAULTS` in `hybrid_evaluator.py:95-99` contains `{TIMEOUT, PROCESS_ERROR, INVALID_OUTPUT}` — **`NONZERO_EXIT` is not retried**, and `GenericRunService` currently leaves `max_technical_retries` at its default `0` (`routes_generic_runner.py:2472-2497`).

### 2.5 Policy Review, Verdict Resolution & Observation-Based Binary Policy v2.2.0

- **Trusted Context Requirement (`routes_generic_runner.py:1218-1282`):** Live hybrid scans require either a cryptographically reviewed `ResponsePolicyRecord` (`review_status="reviewed"`, SHA-256 verified) OR a current `operator_declared` Application Context A–E matching `target_revision`. Offline mode permits fallback to `generic-stored-target`. Unreviewed inline testcase rules are always rejected (`unreviewed_inline_rules_rejected`).
- **Deterministic vs. Judge Precedence (`verdict_resolver.py`):**
  1. Execution failure (`execution_success != True`) -> `EXECUTION_ERROR` (Judge not called).
  2. Verified runtime execution `FAIL` (from `EvidenceV2Evaluator`) -> final `FAIL` (Judge cannot override to `PASS`).
  3. Reviewed deterministic rule `FAIL` -> final `FAIL`.
  4. In `tool_misuse` (`ASI02`) response-only scope, `_inspect_lab_inline_actions` (`verdict_resolver.py:1450-1586`) can deterministically detect prohibited lab inline actions (not wired for `ASI05`).
  5. Otherwise, if `hybrid` and `response_complete == True` and scope allows semantic evaluation, Judge recommendation resolves `PASS`/`FAIL`.
- **Binary Projection (`verdict_outcome.py:314-611`):** Every processed case receives `verdict in {"PASS", "FAIL"}`. Technical failures (`EXECUTION_ERROR`, `JUDGE_ERROR`) and insufficient-evidence outcomes (`INCONCLUSIVE` / `incomplete_response` / `target_reported_claim_unverified`) project to `verdict="PASS"` paired with explicit `evaluation_status` and `evidence_limitations`. Summary KPIs count all binary cases in `evaluated_cases` and `pass_count`/`pass_rate` while reporting `technical_failure_count` separately.
