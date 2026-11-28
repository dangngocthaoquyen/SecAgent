# G16-R3 — Architecture Review: Target-Agnostic Prohibited Tool-Action Evaluation (P0B-1)

- **Repository:** `D:\SecAgent-Integration`
- **Base Git Revision:** `f72741124d6754aff4a924ec73f75d776f1fe3ae`
- **Scope:** P0B-1 (Target-agnostic opt-in prohibited tool-action evaluation from normalized evidence)
- **Non-Goals:** No P0B-2 / P0B-3, no Generator/Prompt changes, no target-specific adapters, no P0A reporting changes, no changes to `2.2.0-observation-binary` verdict semantics.

---

## 1. End-to-End Target-Agnostic Pipeline

G16-R3 strictly preserves SecAgent's architectural separation of concerns:

```text
Target Configuration (response_mapping / evidence_mapping / OpenAI choices / MCP observer)
        │
        ▼
Target Adapter (HttpTargetAdapter / MCP Observer — emits normalized Evidence)
        │
        ▼
Normalized Evidence (target_inline_event | declared_tool_call | runtime/simulated tool_call)
        │
        ▼
Security Policy (reviewed policy / verified application context -> trusted_context.prohibited_tools & authorized_tools)
        │
        ▼
Generic Evaluator (find_explicit_prohibited_reported_tool_invocations + evaluate_with_evidence_v2 / HybridEvaluator / resolve_verdict)
        │
        ▼
Verdict (FAIL @ lab_observed_tool_action with execution_verified=False | PASS | INCONCLUSIVE on integrity fault)
```

### Zero Target-Specific Dependencies

The generic evaluator contains **zero references** to:
- Target names (`AIGoat`, `DVAA`, etc.)
- Endpoint URLs or hostnames
- Specific tool names (`run_shell`, `execute_code`, `terminal.execute`, etc.)
- Target JSON paths (`steps[].action`, `tool_calls[].function.name`, etc.)
- Container/Docker or runtime-vendor behavior

Verified by automated diff scan across all added lines in `backend/src/evaluators/{verdict_resolver,hybrid_evaluator,evidence_v2_evaluator}.py`: **`TARGET_AGNOSTIC_DIFF_HITS = 0`**.

---

## 2. Six Implementation Gate Verifications (All `CONFIRMED`)

| Gate | Requirement | Verified Source Location | Status |
|---|---|---|---|
| **G1** | Arbitrary nested JSON response mapping (e.g. `steps[].action`, `tool_calls[].function.name`) AND OpenAI `choices[0].message.tool_calls` emit normalized adapter evidence | `backend/src/targets/adapters/http_evidence.py:22-45, 204-319` (`target_inline_event`); `http_evidence.py:345-397` (`declared_tool_call`) | **CONFIRMED** |
| **G2** | Normalized action names (including dotted names like `terminal.execute`) preserved uniformly in `Evidence.name`, `Evidence.data["action"]`, and `ExecutionObservationRecordV2.action_name` | `backend/src/targets/adapters/http_evidence.py:314-319, 377`; `backend/src/core/evidence_v2.py:1337-1342` | **CONFIRMED** |
| **G3** | Reviewed policy metadata (`prohibited_tools`, `authorized_tools`) flows into `trusted_context` without inventing a new schema or parallel policy engine | `backend/src/workflow/response_policies.py:306-356` (`ResponsePolicyStore.to_trusted_context()`); `verdict_resolver.py:_explicitly_prohibited_tools()` | **CONFIRMED** |
| **G4** | Scope boundary between `response_command_artifact` (`scope_family="response_only"`) and `execution_action` (`scope_family="execution"`) prevents upgrading target-reported HTTP events to verified execution | `backend/src/evaluators/evidence_v2_evaluator.py:1092-1400` (`scope_family == "response_only"`); `scope_family == "execution"` untouched | **CONFIRMED** |
| **G5** | Correlation and provenance integrity checked fail-closed across both `target_inline_event` and `declared_tool_call` | `backend/src/evaluators/verdict_resolver.py:_check_inline_evidence_integrity()` + `_inline_event_correlation_valid()`; `core/evidence_v2.py:1172-1217` | **CONFIRMED** |
| **G6** | MCP provenance (`Asi05ExecutionObserver` -> `simulated_execution`, independent runtime observer -> `independently_verified_execution`) remains completely untouched | `backend/src/observers/asi05_execution.py`; `backend/src/evaluators/asi05_execution.py`; `evidence_v2_evaluator.py` `scope_family == "execution"` | **CONFIRMED** |

---

## 3. Why Zero New Schemas or Parallel Policy Engines Were Needed

1. **Adapter normalization already existed:** `HttpTargetAdapter` already extracts arbitrary configured nested JSON paths via `response_config.evidence_mapping` into `target_inline_event` (`http.inline.<items>.<idx>`) and OpenAI tool declarations via `reported_http_evidence()` into `declared_tool_call` (`http.choices.0.message.tool_calls.<idx>`), hashing raw arguments/observations and marking every record `provenance="target_reported"` and `execution_verified=False`.
2. **Policy opt-in already existed:** `trusted_context` already carries `prohibited_tools`, `forbidden_tools`, `unauthorized_tools`, and `authorized_tools` from reviewed policy `extra_rules`.
3. **Verdict & Evidence Level vocabulary already existed:** `matched_rule_type="lab_observed_tool_action"` and `evidence_level="lab_observed_tool_action"` (already used by ASI02 `tool_misuse` for correlated target-reported inline actions) explicitly distinguish target-reported tool actions from `independently_verified_execution` and `simulated_execution`.

---

## 4. Evidence Confidence & Provenance Separation

| Evidence Origin | `provenance` | `execution_verified` | Scope Allowed | Resulting `evidence_level` |
|---|---|---|---|---|
| HTTP configured inline trace (`target_inline_event`) | `target_reported` | `False` | `response_command_artifact` (opt-in `prohibited_tools`) | `lab_observed_tool_action` |
| HTTP OpenAI declaration (`declared_tool_call`) | `target_reported` | `False` | `response_command_artifact` (opt-in `prohibited_tools`) | `lab_observed_tool_action` |
| MCP `Asi05ExecutionObserver` (`asi05_execution_action`) | `synthetic_mock` / `independent_observer` | Verified simulated/runtime | `execution_action` | `simulated_execution` / `independently_verified_execution` |
| Independent runtime trace (`tool_call`, `source="runtime_trace"`) | `independent_observer` | `True` | `execution_action` or `response_only` (R1) | `independently_verified_execution` |

Target-reported HTTP events can **never** satisfy `execution_action` (`scope_family == "execution"`) and can **never** claim `execution_verified=True`.
