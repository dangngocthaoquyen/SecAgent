# Production Runner: opt-in HybridEvaluator integration

This change wires the existing evaluator into Runner and the existing native
execution entry point. There is no second evaluator, verdict schema or harness.
All validation in this phase was offline; no DVAA/DeepSeek calls were made.

## Selection and backward compatibility

`Runner()` still uses ResponseEvaluator. `Runner.run(...)` still returns the same
EvaluationResult. New keyword-only configuration selects hybrid behavior:

```python
from testing import Runner, RunnerEvaluationConfig

runner = Runner(
    executor=offline_executor,
    evaluation_config=RunnerEvaluationConfig(
        mode="hybrid", judge_enabled=True, max_judge_calls=2,
    ),
    judge_provider=trusted_offline_fake,
)
result = runner.run(reviewed_case, target, manually_supplied_input)
report = runner.last_report
```

The offline providers/executors above are dependency-injected test doubles. A
complete in-memory example is in tests/test_runner_judge_integration.py, which
uses the default registered goal_hijacking attack module and the existing Pi
provider/parser with an in-memory ProcessRunner. It never starts Pi or HTTP.

`RunnerEvaluationConfig()` defaults to rule_only, Judge disabled, zero budget and
no live permission. `mode="hybrid"` alone is also safe: unresolved semantic cases
report judge_disabled without delegating. Enabled hybrid requires a trusted injected
offline provider, or explicit allow_live_judge=True plus PiEvaluatorConfig. Direct
Pi provider injection without live opt-in is rejected. A custom provider is trusted
caller-supplied code; an arbitrary injected object cannot be sandboxed or proved
network-free by its interface alone.

Existing evaluator= injection is retained as a legacy advanced API. It is marked
custom in reporting and cannot be combined with the new configuration/provider
arguments. Its caller owns its policy/diagnostics; use evaluation_config for the
enforced Runner budget and integrated Hybrid reporting. No blanket network/budget
guarantee is made for arbitrary custom evaluators executing caller-supplied code.

## Native entry point

backend/scripts/run_native_smoke.py now uses RunnerEvaluationConfig. Its default
remains rule_only. It accepts --evaluation-mode hybrid, --enable-judge,
--allow-live-judge and --max-judge-calls. Live operation requires the explicit flags
and configured Pi credentials by environment name; no credential values belong in
arguments. --pi, --judge-provider, --judge-model (default deepseek-v4-flash),
--judge-timeout (default 90), --judge-max-output-bytes and repeatable
--judge-credential-env configure the existing provider.

--prompt-file optionally supplies a manual TestInput without reading any payload
repository. The selected testcase still loads through TestCaseLoader and must use
a registered compatible attack module. No testcase or payload file was modified.
Without --prompt-file the existing payload-rendering behavior is unchanged. The
native command still executes the configured target: network-free Judge defaults
do not mean the target itself is offline.

After K provides a reviewed case, the native command shape is:

```text
python backend/scripts/run_native_smoke.py --target-config <reviewed-target.yaml> --testcase <K-reviewed-case.yaml> --prompt-file <public-manual-input.txt> --evaluation-mode hybrid --enable-judge --allow-live-judge --max-judge-calls 1 --judge-timeout 90 --judge-model deepseek-v4-flash --output-dir <new-local-results-directory>
```

This is documentation, not approval or execution of a live command. The existing
native top-level summary fields are preserved; its additive evaluation field
contains Runner.last_report. Reports use exclusive file creation and are local.

## Invocation and resolution policy

Supported deterministic results retain the existing precedence. HybridEvaluator
still checks semantic.enabled/category/skill compatibility, builds requests with
EvaluationRequestBuilder/SkillBundleLoader and uses the existing validator and
VerdictResolver. Unknown/false completeness blocks semantic PASS; supported FAIL
may resolve with unknown completeness. HTTP 200/finish_reason stop is not trusted
completeness. Provider errors/invalid citations never become semantic PASS/FAIL.
The existing deterministic sufficiency policy was not broadened or rewritten.

The Runner configuration wraps the existing provider with an atomic reservation
counter. Its budget is shared across all run() calls on that Runner instance,
not reset per testcase. Disabled and exhausted calls return structured faults;
they do not delegate. Errors, invalid output and timeouts consume reservations
and are not retried. Short-circuited rules and disabled calls consume no slots.
Use one Runner for the selected sequential batch; creating another Runner creates
another explicitly configured budget. Runner report snapshots are sequential, not
a concurrent batch API, although provider reservation itself is thread-safe.

The limit counts provider.evaluate attempts (Pi invocations), not independently
observable service-internal HTTP operations. Runner performs no retries; this
change does not add a retry loop inside the third-party Pi installation.

## Reporting and sanitization

Runner.last_report and optional report_sink retain target/case/input identity,
timestamp, configured mode and testcase strategy, execution status, response text,
trusted completeness, normalized evidence identities/scopes, baseline and effective
deterministic results, Judge classification/recommendation/reason/citations,
JSON validation status, request and skill hashes, exit/fault/timing diagnostics,
resolved final result, downgrade reason and budget use/remaining slots. A run with
no executed evaluation does not invent a deterministic result. Stale diagnostics
are cleared before every run; reporting failure cannot change the verdict.

Hybrid diagnostic semantic_invoked means semantic fallback was attempted at its
provider boundary; judge_disabled/budget_exhausted may still block delegation.
The used budget counts actual delegated attempts. No raw invalid Judge JSON or
private stderr is persisted. Malformed recommendations have unavailable class/
citation fields rather than fabricated parsed results.

Headers, raw transport bodies, arbitrary event arguments/results and raw transport
error strings are excluded from the report. Values of configured credential env
names (target credential_refs and Pi credential_env) are redacted even if echoed
inside a response/citation/reason. The original execution/observation objects and
returned EvaluationResult are not mutated; redaction is a reporting copy. Arbitrary
private target content still requires caller data policy, and redacted excerpts
must not be confused with byte-identical provider input. Report sinks receive a
copy and cannot rewrite the resolved result.

## Offline verification and evidence hygiene

```powershell
$env:PYTHONPATH='backend/src'
python -m pytest backend/tests/test_runner_judge_integration.py backend/tests/test_runner.py backend/tests/test_hybrid_evaluator.py backend/tests/test_dvaa_judge_flow.py backend/tests/test_independent_judge.py backend/tests/test_external_evaluator_connector.py -q
python -m pytest backend/tests -q -p no:cacheprovider
```

172 focused tests passed; full regression: 488 passed. The full suite also passed
with an in-process audit hook rejecting all open() access under workspace results/.
The new production tests use in-memory cases only, not K's testcase YAML or payloads.
Existing historical regression tests remain unchanged.

The reviewed public Gate 4 capture was copied byte-for-byte into
backend/tests/fixtures/judge/dvaa-asi01-observations.json and both replay test modules
now use that path. The original capture/results remain untouched. .gitignore now
excludes Judge runtime outputs, week5 smoke outputs and local auth/workspace paths.
No tests require those disposable live artifacts; the fixture README records scope.

A complete executed offline Runner -> Hybrid -> FakeJudge example is saved locally
at results/judge-validation/production-runner-offline.json: deterministic
INCONCLUSIVE, ORIGINAL_GOAL/PASS recommendation, valid JSON/citation, completeness
unknown, resolved INCONCLUSIVE with an explicit downgrade reason, budget 1/1 used.
This is a synthetic plumbing example, not new DVAA or Judge accuracy evidence.

## Files and staging recommendation

Source: testing/runner.py, testing/evaluation_config.py, testing/__init__.py,
evaluators/hybrid_evaluator.py (diagnostics only), integrations/external_evaluator/models.py
(disabled/exhausted fault codes), and scripts/run_native_smoke.py.
Tests: test_runner_judge_integration.py and the two updated replay test paths.
Fixtures: tests/fixtures/judge JSON plus README. Documentation/hygiene: this guide,
root README and .gitignore. Prior core/models/evaluation.py and verdict_resolver.py
changes remain in the worktree from the accepted PoC and are not new policy here.

Stage infrastructure with its tests/fixtures and required target configs first;
stage developer scripts/docs separately with their corresponding tests. The native
entry point was already untracked on this branch: its full file must be included,
not just the new wiring lines. Review the prior model/resolver modifications as a
separate PoC prerequisite if not already staged. Keep pre-existing RAG/native-smoke
work ownership distinct. Do not use a blanket add of the worktree. Runtime reports,
credentials, auth stores and historical evidence remain local; no files were deleted.

## Remaining ASI blockers

K owns testcase definitions, payloads and rubric policies. Q owns wiring, normalized
evidence, call policy and reporting. ASI01 still needs real lower-trust provenance
and trusted completion instrumentation for stronger claims. ASI02 needs agreed
authorized-action policy and trusted scoped action traces. ASI03 needs matching
type/skill registrations and identity/authorization transition evidence. ASI05
needs registrations and verified execution/effect evidence. No new categories were
implicitly enabled, no tool/privilege/execution events were invented, and the
paired simulated user-message PoC does not validate those categories or calibrate
Judge confidence/accuracy. No protected K files or DVAA files were changed.
