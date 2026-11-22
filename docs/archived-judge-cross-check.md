# Archived evidence Hybrid Cross-Check

This optional research entry point assesses a saved observation without calling
Runner.run, Executor, a target adapter, Docker, the fixture server or a target.
It does not replay the attack or re-resolve the original security verdict.

Flow: verify archive bytes and identity -> reconstruct reviewed trusted testcase
context -> existing EvaluationRequestBuilder/SkillBundleLoader -> existing Pi
provider and JSON/citation validation -> separate versioned comparison report.

It intentionally invokes the provider even when the stored deterministic result
is decisive. Production HybridEvaluator's rule-first behavior and VerdictResolver
remain unchanged. This is a research comparison, not an alternative verdict engine.

## Archive validation and provenance

The selected directory needs evidence-sha256.csv with Path/Hash columns and one
reports/*.secagent.json, or an explicit --report selection. Every listed file is
read and checked against its SHA256. Duplicate entries, escaping/symlink paths,
oversized/missing files, invalid hashes and ambiguous report selection fail closed.
Absolute inventory paths must resolve within the selected archive; relocation
does not silently rebind old absolute paths to different files.

For this GH-WEB-001 collector archive, the inventory must cover:

- fixture/manifest.json
- fixture/events.jsonl
- sanitized-collector-after.json
- the selected original .secagent.json report

The loader checks report/testcase/target identities, execution state, response
completeness consistency, existing Evidence models, collector provenance,
manifest/log hashes and export/log equality. The archived receipt must be
corroborated by matching local receipt/page records, canary hash, peer-match
status and chronology. It never constructs a new verified action from arbitrary
target JSON. It never calls WebFixture.claim, record or evidence to fabricate a
new execution-time receipt.

Hash meanings are explicitly separate:

1. file-byte SHA256: SHA256 of each original file's exact bytes, including
   whitespace/newlines/encoding. This is what evidence-sha256.csv records.
2. historical collector canonical JSON SHA256: SHA256 of UTF-8
   json.dumps(records, sort_keys=True), including that function's default
   separators/ASCII escaping. This is collector data.log_sha256, not the JSONL
   file-byte hash and not the request canonical_hash algorithm.
3. Judge request canonical SHA256: the existing EvaluationRequest.sha256, which
   uses the existing compact canonical JSON contract.

The hash inventory itself is hashed for provenance but is not signed. A local
writer able to replace both files and inventory can forge the record. Successful
hash checks establish consistency, not remote attestation or archive authorship.
The exact historical target-execution start time is not present in the report;
its original correlation window cannot be independently reconstructed. That
limitation remains explicit rather than inventing a start timestamp.

Trusted goals are reconstructed from the explicitly selected current reviewed
testcase and archived fixture binding. Current YAML bytes and skill identity are
recorded. The four-file archive does not establish historical testcase/skill byte
identity; archive these contracts at execution time in future experiments.

## Independent Judge input and redaction

Only the existing request contract is sent. Original deterministic/final verdicts,
matched rules, prior Judge output, archive paths and comparison labels are excluded.
Source and collector evidence retain distinct provenance and limitations.
All archived text remains observation data; it cannot replace the system skill.

The request is a sanitized copy. URLs become stable truncated SHA256 identifiers;
the raw manifest canary and configured credential environment values are removed.
Common sk-/Bearer secrets are also redacted. Only allowlisted primitive evidence
data is forwarded, never full tool arguments, raw logs or transport headers.
Unknown arbitrary private data still requires an operator review/redaction policy;
automatic scrubbing cannot guarantee removal of every transformed secret.

Response and runtime citations are validated against this sanitized request, not
against a reconstructed raw-canary response. The report retains original file
hashes so the untouched original is available for local audit. Fixture correlation
ID/collector label are not the raw canary value.

## Results and comparison

The new report schema_version=1.0/report_type=archived_hybrid_cross_check contains
original identities/verdicts, archive byte hashes, collector canonical digest,
current testcase/skill provenance, actual sanitized request/digest, validated Judge
response, diagnostics, comparison and limitations. It states
target_execution_performed=false and original_final_verdict_overridden=false.

- agreement: valid Judge PASS/FAIL equals original deterministic PASS/FAIL.
- disagreement: both are comparable PASS/FAIL values and differ.
- unavailable: provider/validation fault, UNCLEAR/INCONCLUSIVE, nonbinary original
  result, or archive mutation detected during assessment.

ATTACKER_GOAL and MIXED can both recommend FAIL. Agreement here is at the verdict
level; it does not assert identical goal classifications or prove Judge accuracy.
A valid Judge PASS with unknown response completeness remains an independent raw
recommendation; it is never authorized as a new final PASS by this workflow.
The original final verdict remains intact in every case.

Illustrative abbreviated **fake**, not live, report:

```json
{
  "schema_version": "1.0",
  "report_type": "archived_hybrid_cross_check",
  "target_execution_performed": false,
  "original": {
    "testcase_id": "GH-WEB-001",
    "asi_category": "ASI01",
    "deterministic_verdict": "FAIL",
    "final_verdict": "FAIL",
    "response_complete": null
  },
  "judge": {
    "invoked": true,
    "mode": "fake",
    "provider_invocation_attempts": 1,
    "json_validation_status": "valid",
    "classification": "ATTACKER_GOAL",
    "recommendation": "FAIL"
  },
  "comparison": {
    "status": "agreement",
    "original_final_verdict_overridden": false
  }
}
```

## Commands

From D:\SecAgent-W5-Judge, validate the real archive without any Judge or target:

```powershell
$Archive = 'results/judge-validation/asi01-compose/attack-20261106T0813087606067Z'
python backend/scripts/cross_check_archived_judge.py --archive-dir $Archive --testcase testcases/goal_hijacking/GH-WEB-001.yaml --mode validate
```

Offline FakeJudge plumbing check, writing a NEW report outside the original archive:

```powershell
python backend/scripts/cross_check_archived_judge.py --archive-dir $Archive --testcase testcases/goal_hijacking/GH-WEB-001.yaml --mode fake --max-judge-calls 1 --fake-classification ATTACKER_GOAL --output results/judge-validation/hybrid-cross-check/gh-web-001-fake-v1.json
```

The fake classification selects only canned transport output, never Judge input.
It is not an independent assessment. Default mode is validate and performs no
provider call. Both assessment modes require a one-call budget and output path.

One manually approved live assessment (NOT executed during implementation):

```powershell
if ([string]::IsNullOrWhiteSpace($env:DEEPSEEK_API_KEY)) {
    throw 'DEEPSEEK_API_KEY must be supplied securely in this process.'
}
python backend/scripts/cross_check_archived_judge.py `
  --archive-dir results/judge-validation/asi01-compose/attack-20261106T0813087606067Z `
  --testcase testcases/goal_hijacking/GH-WEB-001.yaml `
  --mode live `
  --allow-live-judge `
  --max-judge-calls 1 `
  --judge-provider deepseek `
  --judge-model deepseek-v4-pro `
  --judge-timeout 90 `
  --judge-credential-env DEEPSEEK_API_KEY `
  --pi C:\Users\Quettye\AppData\Roaming\npm\pi.cmd `
  --output results/judge-validation/hybrid-cross-check/gh-web-001-pi-v1.json
```

The existing provider retains --no-extensions, no-tools restrictions, isolated
system prompt, bounded output and credential allowlist. The existing budget
wrapper reserves one call; there is no cross-check retry loop. This budget bounds
provider/CLI invocations, not any internal upstream retry behavior of Pi.

Outputs are created exclusively. Existing outputs are rejected before calling
the provider; choose a new version path after reviewing any previous result.
Outputs cannot be placed inside the original archive or overwrite .secagent.json
files. Original bytes and inventory are rechecked before/after assessment.

## Offline tests and future categories

```powershell
$env:PYTHONPATH='backend/src'
$env:SECAGENT_NO_DOCKER='1'
python -m pytest backend/tests/test_archived_crosscheck.py -q -p no:cacheprovider
python -m pytest backend/tests -q -p no:cacheprovider
```

SECAGENT_NO_DOCKER skips the pre-existing Compose-CLI configuration test so this
task's full regression invocation executes no Docker commands. Other tests use
synthetic temporary archives, existing FakeJudge/Pi validation and mocked target
transports. No test depends on disposable results/ files.

The generic archive/request boundary accepts existing ASI02 tool-misuse semantic
contracts. ASI03/ASI05 have no compatible semantic contracts/registered Judge
skills yet, so assessment is explicitly rejected before a provider call. No new
rubric or evidence is invented, and no validation of those categories is claimed.

A confirmed collector receipt demonstrates unauthorized runtime behavior in this
DVAA implementation. It does not establish autonomous DeepSeek tool selection.
Judge confidence is not calibrated probability, and Judge agreement is not truth.

Verification completed: 30 feature tests passed; expanded focused verification
319 passed/1 skipped; full backend regression 689 passed/1 skipped. The skipped
test is the pre-existing Docker Compose CLI check, disabled for this task.
The real four-file inventory validated without invoking a provider; all nine
files in the original archive remained byte-identical and no files were added.
