# Portable Promptfoo-schema fixtures

These are synthetic test fixtures, not an external research dataset, a Promptfoo
execution, or human-reviewed security labels. All 30 prompts were newly authored
for offline tests and refer only to a fictional FixtureAction and fixture projects.
They preserve the excessive-agency/confirmation-bypass input theme, not the
original attack wording or coverage. No source prompt was copied.

The reviewed source pair was testcases_dvaa_codebot_asi02.json (SHA256
37de80b4588801599a60c676dfd2a486609cf5a91d66ae9bfff1c0a85db0aa9a)
and redteam (1).yaml (SHA256
0d2a41f083657656446e9692c6a030406944ec0988c57d3f92e911cf394fd1f5).
Those fingerprints identify the schema references, not these synthetic fixtures.
The original files remain untouched in private storage and the Phase 0 checkpoint.

Preserved contracts:
- 30 cases TC0001 through TC0030, stable order and paired JSON/YAML prompts.
- JSON envelope version/source/platform/bot/run labels for importer compatibility.
  DVAA/codebot/asi02 are schema test values, not evidence of a target execution.
- Null description and per-case strategy_id; YAML root strategy basic.
- vars.prompt, assertions/assert type and metric, pluginId/plugin_id, metadata
  objects, options and extra. Severity medium is source-style metadata, not a verdict.
- Exact prompt/assertion/metadata correspondence across the two fixture formats.

Sanitization is by construction: only the listed schema fields and public metadata
constants are retained. Original prompt text, provider configuration, endpoints,
headers, credentials, responses, grading results and security/human labels are not
included. Both roots explicitly declare synthetic fixture provenance. Assertions
are untrusted import metadata and must never become SecAgent verdicts.

Thirty rows are retained because existing tests exercise full 30-case batching,
request budgeting, isolation, correlation and native report persistence. This pair
replaces machine-specific file dependencies; it does not replace the external
research datasets. Transport/Judge fixtures remain mocked.

The mismatch regression constructs an unrelated YAML in pytest tmp_path instead
of reading the machine-local redteam.yaml. It keeps exact matching, a pinned
SHA256 for this JSON fixture, and the disjoint-prompt negative check. Original
dataset integrity belongs to the private research archive, not this synthetic
regression fixture.
