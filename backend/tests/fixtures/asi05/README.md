# ASI05 Judge correctness fixtures

`reviewed_policy_snapshot.json` is an exact byte copy of the reviewed CodeBot
policy with revision `81b81f40c188989dd3f30750f5e63af79f0ae4eebb98ba3a61a729b9f5683558`.
The contract test pins its file SHA256 and the current trusted Markdown bundle
SHA256. These fixtures are independent of historical framework verdicts.

`semantic_cases.json` contains separately reasoned policy labels for A, B, C,
D1, D2, E, and I. They are **proposed policy-analysis labels**, not measured
Pi/DeepSeek outputs or human consensus. D2 deliberately records the current
policy's unresolved authorization ambiguity as `UNCLEAR`.

The semantic pilot additionally marks D1, D2, and E `NEEDS_HUMAN_REVIEW`:
D1's authorization appears only in untrusted attacker input; D2's metadata
boundary is not explicit in the policy; E is a bare claim of execution with no
command artifact or runtime receipt. The authored labels remain unchanged.

The automated tests use a Fake Judge to check request construction, evidence
provenance, gates, output validation, resolver behavior, and provider faults.
Passing these tests does not establish production Judge semantic accuracy.

For a future semantic study, first obtain an independent blinded review of each
fixture's label and rationale. Pin the reviewed policy revision, skill bundle,
Judge configuration, response bytes, and response completeness contract. Then
submit each saved response once through the production HybridEvaluator and Pi
provider **without running a Target**, preserving raw recommendation,
classification, exact citation, fault, and resolved verdict separately. Compare
against the independent labels only after all Judge outputs are captured. Treat
invalid output and incomplete observation as unresolved, never as safe PASS.
This procedure is documentation only; no live Judge run is part of these tests.
`backend/scripts/run_asi05_semantic_pilot.py` implements validation, a
network-free dry-run, and a separately gated execute path. Its provisional
agreement rate excludes D1, D2, and E until independent review resolves them.
