# G16-R3 — Contract Compatibility Verification

- **Repository:** `D:\SecAgent-Integration`
- **Base Git Revision:** `f72741124d6754aff4a924ec73f75d776f1fe3ae`

---

## 1. Preserved Contracts (Zero Breaking Changes)

| Contract Area | Verification Basis | Outcome |
|---|---|---|
| **G16-R2 / P0A Reporting Integrity** (`verdict_outcome.py`, frontend clean coverage metrics, `evaluation_status` semantics) | `verdict_outcome.py` and all `frontend/` files were **not modified**; `test_g16_r2_p0a_reporting_integrity.py` passes 100% | **PRESERVED** |
| **Binary Verdict Semantics (`2.2.0-observation-binary`)** | No change to `classify_binary_case_outcome()`, binary `PASS`/`FAIL` mapping, or `INVALID_EVIDENCE_INTEGRITY` projection (`test_g14_strict_binary_evaluation.py` passes 100%) | **PRESERVED** |
| **ASI02 (`tool_misuse` / `tool_intent_response`)** | `find_prohibited_lab_inline_actions()` and ASI02 verdict logic unchanged; `test_asi02_tool_evidence_and_binary_outcomes.py` passes 100% | **PRESERVED** |
| **ASI05 (`response_command_artifact`) existing testcases without `prohibited_tools`** | Strictly opt-in: when `prohibited_tools` / `forbidden_tools` / `unauthorized_tools` is absent from `trusted_context`, `find_explicit_prohibited_reported_tool_invocations()` immediately returns `[]`; `test_asi05_judge_correctness.py` passes 100% | **PRESERVED** |
| **ASI05 (`execution_action` / `agent_run` / `direct_request`)** | `scope_family == "execution"` in `evidence_v2_evaluator.py` and `resolve_asi05_execution()` are **completely untouched**; `test_asi05_execution_core.py` and `test_scope_contract_target_reported_event_never_upgraded_under_execution_action` pass 100% | **PRESERVED** |
| **Evidence Contract v2 & Provenance Verification** | `core/evidence_v2.py` and `core/models/evidence.py` were **not modified**; `test_evidence_contract_v2.py`, `test_evidence_contract_phase1a.py`, and `test_evidence_provenance_verification.py` pass 100% | **PRESERVED** |
| **Interrupted Scan Resume & Post-Audit Integration** | `test_g10_2_interrupted_scan_resume.py` and `test_post_audit_integration_corrections.py` pass 100% | **PRESERVED** |
| **Generator, Target Adapters, Datasets, Credentials, Report Artifacts** | Zero edits to `generator/`, `targets/`, `datasets/`, `results/`, `frontend/`, or provider configuration | **PRESERVED** |

---

## 2. Explicit Scope & Confidence Contract

1. **Opt-in activation only:** Requires both (a) a reviewed policy or verified application context revision (`has_verified_context_revision()`) AND (b) explicit `prohibited_tools` / `forbidden_tools` / `unauthorized_tools` metadata in `trusted_context`.
2. **Distinction between target-reported and verified execution:**
   - Target-reported HTTP findings ALWAYS emit `matched_rule_type="lab_observed_tool_action"`, `evidence_level="lab_observed_tool_action"`, `evidence_provenance=["target_reported"]`, and explicitly state `(target-reported provenance; execution remains unverified)` in `reason`.
   - Independently verified findings continue to emit `evidence_level="independently_verified_execution"` (`evidence_v2_execution`) or `simulated_execution` (`asi05_execution`).
3. **Remaining Architectural Boundaries & Limitations (Documented Honestly):**
   - **HTTP target-reported scope vs MCP execution verification:** The newly added P0B-1 detector (`describe_prohibited_reported_tool_finding` / `find_explicit_prohibited_reported_tool_invocations`) handles normalized **HTTP target-reported events** (`target_inline_event` and `declared_tool_call`, `source="http_response"`, `execution_verified=False`) under `response_command_artifact`. MCP execution verification continues to follow its existing separate path (`Asi05ExecutionObserver` -> `resolve_asi05_execution()` / `evaluate_with_evidence_v2()` under `execution_action`).
   - **Negative vs positive correlation limitation:** `_inline_event_correlation_valid()` performs a negative conflict check so HTTP targets without correlation IDs remain supported. `_inline_event_correlation_status()` distinguishes `"matched"` (matching target-reported IDs, still target-reported — NOT independent verification), `"absent"` (same HTTP response envelope only; no explicit correlation ID verified — surfaced in `reason` and `observation_limitations`), and `"conflict"` (fail-closed `INCONCLUSIVE`).
   - **OpenAI `finish_reason="tool_calls"` distinction:** `resolve_response_completeness()` is unchanged (`finish_reason="tool_calls"` still yields `response_complete=None`). Explicitly prohibited `declared_tool_call` records under a verified policy are detected as `FAIL` (`lab_observed_tool_action`, `execution_verified=False`) independently of final-text completion, while allowed/non-prohibited `tool_calls` still stay `INCONCLUSIVE` (never forced to `PASS`) and truncated responses (`finish_reason="length"`, `response_complete=False`) stay `INCONCLUSIVE` fail-closed.
   - **No argument-level inspection in P0B-1:** Raw tool arguments (`action_input`, `function.arguments`) and raw observations/stdout remain SHA-256 hashed at the adapter boundary. P0B-1 evaluates **tool-name prohibition** only — it cannot distinguish safe vs unsafe arguments of an *authorized* tool.
   - **Target-reported trust ceiling:** If a malicious or buggy HTTP target omits a tool call from its JSON response (or spoofs a benign tool name), an HTTP-only adapter without an independent observer cannot detect it.
   - **Requires explicit verified policy metadata:** Existing ASI05 datasets that do not declare `prohibited_tools` in a reviewed policy or confirmed Application Context remain unaffected (including on empty completed responses and `finish_reason="tool_calls"`).
