# SecAgent shared Hybrid Judge integration

Date: 2026-11-19. Scope: ASI01, ASI02, ASI03 and ASI05 on the current DVAA
lab. **Decision: shared response-Judge wiring is implemented; live semantic
verification remains blocked in this process by absent credential.** Action
conclusions for ASI02 and ASI05 remain evidence-limited. No target or external
Judge request was made during this integration change.

## Existing route and remaining wiring

| ASI | Evaluation scope | Existing Judge path | Missing wiring or prerequisite |
| --- | --- | --- | --- |
| ASI01 | Goal preservation in a complete response; separate collector-backed Web scope | `Asi01BatchWorkflow` uses `ControlledDispatcher.hybrid_config` and Runner; decisive rules short-circuit Pi; ambiguous responses use trusted goal-hijacking Skill | No shared infrastructure gap. The controlled live GH-C01/GH-001 pair was rule-only, so its semantic Pi path was not live tested. |
| ASI02 | Tool misuse / action | `HybridEvaluator` and tool-misuse Skill exist; resolver requires verified scoped action for FAIL and complete trusted trace for absence-based PASS | The current TM-002 live direct-MCP path has no correlated handler receipt or reviewed semantic action contract. `ToolBotLabBatchWorkflow` is intentionally offline synthetic and rule-only. Enabling Pi cannot supply the missing evidence or prove Agent-selected action. |
| ASI03 | Reviewed `identity_claim_response` | `GenericImportedBatchWorkflow` builds reviewed target-policy context and routes through the same dispatcher, Runner, HybridEvaluator, Pi provider and resolver | No response-path wiring gap. Live Pi is blocked by configured credential absence in this process; privilege-action scope separately lacks independent principal/action trace. |
| ASI05 | Reviewed `response_command_artifact`; separate `execution_action` | Imported response workflow uses the same Hybrid path and trusted ASI05 response Skill. Execution core uses the same Runner/evaluator boundary but a deterministic evidence resolver | Response path is wired. Execution policy remains draft; live direct-MCP trace is partial and has no correlated handler/effect receipt. The response Skill is not used to infer execution. |

The shared pipeline is:

```text
Reviewed testcase / target / policy binding
 -> Target adapter -> Runner -> observer / normalized evidence
 -> deterministic evaluator -> EvaluationRequestBuilder when eligible
 -> shared PiEvaluatorProvider (one bounded attempt per case)
 -> VerdictResolver -> Native Report
```

The [local launcher](../../start_secagent_local.py) already takes one
`--judge-config` file and forwards only its named credential environment
variables to the Workflow API process. The
[Workflow API](../../backend/src/workflow/api.py) loads that same
`RunnerEvaluationConfig` once into
[ControlledDispatcher](../../backend/src/workflow/dispatch.py). Each selected
case gets a fresh Runner and budget of at most one Judge call; decisive rules
and evidence gates do not consume it. There is no separate ASI-specific Pi
provider or credential configuration. Skill choice comes from the trusted
testcase category, never target response text. Reviewed ASI03/ASI05 policies
are pinned and rechecked before dispatch by the imported workflow.

## Changes in this sprint

- [evaluation_config.py](../../backend/src/testing/evaluation_config.py):
  added a target-independent live Pi preflight for Hybrid opt-in, exactly
  one attempt per testcase, valid credential environment names, credential
  **presence only**, and executable availability. It emits fixed diagnostics
  without secret values.
- [start_secagent_local.py](../../start_secagent_local.py),
  [workflow/api.py](../../backend/src/workflow/api.py), and the existing
  [ASI03 opt-in pilot](../../backend/scripts/pilot_asi03_dvaa_response.py)
  now reuse that preflight. The API reports missing credential as a specific
  Judge startup fault before server or target dispatch.
- [Runner](../../backend/src/testing/runner.py),
  [HybridEvaluator](../../backend/src/evaluators/hybrid_evaluator.py) and
  [EvaluationRequestBuilder](../../backend/src/evaluators/evaluation_request_builder.py)
  now apply the configured credential-echo rejection to **every** semantic
  request. Earlier it was only reached for the reviewed ASI01 prepared-input
  path. A blocked request stays INCONCLUSIVE with `input_rejected`, zero
  Judge attempts, and report redaction.
- [Offline tests](../../backend/tests/test_unified_judge_configuration.py)
  cover the common preflight, four allowlisted Skill identities, ASI02
  no-implicit-Judge gate, ASI03 context/skill/request routing, credential
  echo rejection, fixed startup diagnostic, and one-call budget. Existing
  tests cover ASI01/ASI03/ASI05 reviewed policy gates, citation validation,
  provider faults, evidence provenance and Native Reports.

No reviewed Policy, trusted Skill, VerdictResolver, historical result or
consensus label was changed. No DVAA-specific condition was added to Runner,
HybridEvaluator, VerdictResolver, evidence models or reporting.

## One operator-owned configuration

The present nonsecret Runner configuration is
`%LOCALAPPDATA%\SecAgent\asi03-judge.json`. Its filename is historical;
the contents are the generic `RunnerEvaluationConfig`: `mode=hybrid`,
`judge_enabled=true`, `allow_live_judge=true`, `max_judge_calls=1`,
provider `deepseek`, model `deepseek-v4-flash`, and credential environment
name `DEEPSEEK_API_KEY`. The Pi executable exists and its `--version`
command exited 0. A single file can be reused for every reviewed semantic
ASI; no per-ASI credential is needed. The key itself remains in the operator
process environment and is never stored in this repository, testcase, policy
or report. The launcher forwards it only to the Workflow API, and Pi forwards
only the configured name to its isolated subprocess.

The common UI/API launcher supports separate, explicit batch modes with the
same configuration path:

```powershell
python start_secagent_local.py --enable-asi01-batch --judge-config "$env:LOCALAPPDATA\SecAgent\asi03-judge.json"
python start_secagent_local.py --enable-custom-imported-batch --enable-imported-live-local --judge-config "$env:LOCALAPPDATA\SecAgent\asi03-judge.json"
```

The second mode admits reviewed ASI03 and ASI05 **response** cases. Batch
modes remain separate local sessions by existing design; reusing the same
file does not create four configurations. A case must still pass target,
dataset, policy, skill, disclosure, completeness and operator authorization
gates. Rule-only selection remains available.

## Offline and live verification

Focused regression after the shared changes: **143 passed, 0 failed** across
HybridEvaluator, ASI01 input/native batch, ASI03 reviewed contracts, ASI05
live evidence core, Workflow dispatch and new tests. A subsequent
Workflow-CLI/preflight run: **41 passed, 0 failed** (overlapping tests, so
the counts must not be added as distinct cases). The final six unified
configuration tests also passed after adding the ASI05 response disclosure
case. A separate Runner/ASI05 execution/ASI02 tool pipeline regression
finished **46 passed, 0 failed**. These runs overlap in coverage, so no
distinct-test total is claimed. No full repository suite or new semantic
accuracy study was run.
The focused local-launcher credential-forwarding regression also passed
(**1 passed**).

The current operator-owned config parsed and passed its nonsecret mode,
provider, model, executable and one-call checks. Its configured credential
was **absent in this process**; shared preflight returned
`Configured Judge credential is unavailable in this process.` Therefore
the required live ASI03 TC0001 check stopped **before any Target or Pi
request**. The previously verified TC0001 reviewed policy/dataset/prompt/
target revisions were checked again offline and matched; they remain pinned
in the official workflow and the existing ASI03 pilot. There is no new
semantic assessment, recommendation, citation,
verdict or Native Report. The previous TC0001 INCONCLUSIVE was
`judge_disabled` from a pilot without Judge opt-in, not a semantic result.

## Verdict and accuracy limits

- Missing handler receipt, incomplete trace, draft policy or uncorrelated
  evidence produces an evidence-limited INCONCLUSIVE. Pi cannot upgrade
  target-reported success to verified execution.
- Missing credential, Pi process fault or invalid Judge output is a technical
  Judge problem; it must not be presented as a target PASS.
- A direct MCP request is attributed to the tool-service request. It is not
  an Agent-selected invocation; simulated handler execution is not host OS
  execution.
- The disclosure guard blocks configured credential values and the existing
  reviewed ASI01 input patterns. It cannot identify every unknown private
  string in arbitrary Target text; operator data policy and reviewed case
  selection remain prerequisites for external evaluation.
- ASI01's controlled live pair was rule-only. ASI03 has no successful live
  semantic Pi output yet. ASI05's earlier 13/13 agreement concerns selected
  stored response artifacts, not execution or general accuracy. ASI02 action
  accuracy is not validated.

**Next live gate:** start the common imported workflow with the same
operator-owned config in a process where its named credential is present,
select only verified ASI03 TC0001, authorize one target request and one
Judge attempt, then inspect the Native Report's semantic classification,
exact response citation, provider diagnostic and resolved verdict. A claim
of privileged action remains out of scope without independent action
evidence. No ASI01/02/05 batch should be rerun to satisfy this gate.
