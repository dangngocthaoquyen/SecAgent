# Downloadable research reports

Exports are read-only views of the existing reporting repository. They never execute Target, Judge, rules or verdict resolution. No source artifacts, policies or external evidence captures are modified or attached.

## Use

- Terminal Batch Progress: **Download Full Report**, next to **View Reports**.
- Execution Results: **Download Report** on each row.
- Report Detail: **Download Report** beside Back.

The button shows **Preparing export...**, prevents repeated clicks, reports missing/invalid records, and discards a pending response when the selection changes or the component unmounts. No automatic retry occurs. Restart the Reporting API and reload the frontend to load the implementation; this task does not restart operator services.

## API and access boundary

GET `/api/reports/batches/{32-hex-batch-id}/download` returns ZIP.

GET `/api/reports/runs/{32-hex-run-id}/download` returns JSON for a controlled run.

GET `/api/reports/executions/{execution:64-hex-source-hash}/download` returns JSON from the explicitly selected reporting dataset.

All three inherit the existing reporting boundary: local loopback caller, approved localhost Host, same-origin checks, GET-only, no request body or arbitrary query. This is the existing local reporting access model, not a new login or internet-facing authentication system. Controlled runs/batches require the operator-selected `controlled_runs_root`. No caller can choose an arbitrary filesystem root or report path. The existing Vite reporting proxy forwards these GET routes.

Downloads use attachment headers, `Cache-Control: no-store` and existing security headers. Archives are built in memory with a 64 MiB total exported-content bound and at most 128 selected cases. No public export directory is created. The API rejects an active batch, corrupt hash, duplicate run/case or mismatched linkage rather than returning a misleading partial ZIP. Interrupted/cancelled selected cases without reports are represented by explicit `report_available: false` records with no invented security verdict.

## Schema 1.0.0

`secagent-{asi}-{target-id}-{batch-id}.zip` contains:

```text
manifest.json
summary.json
results.csv
reports/TC0001.json
...
```

- Manifest: batch/dataset/revision/target/evaluation-mode/scope/policy identity, recorded timestamps, source state/snapshot hashes and every other archive member's byte SHA256/size. It does not hash itself. Each report member records its original source-report SHA256 separately from its exported-byte SHA256. These are integrity checks, not authenticity signatures.
- Summary: recorded verdict counts including ERROR and unknown; execution statuses; recorded target requests and unknown-count indicators; semantic/provider invocation true/unknown counts and invocation states; response completeness and evidence availability; limitations. Missing provider invocation metadata is never interpreted as zero calls.
- CSV: case ID, ASI, execution status, deterministic verdict, Judge classification/recommendation, final verdict, scope, completeness, citation status and reason. UTF-8 BOM supports Excel. Formula-leading cells are prefixed with an apostrophe; JSON retains their sanitized textual values.
- Case JSON: export envelope plus existing normalized execution record: imported provenance, observations, deterministic/final results, Judge metadata/reason/citations, request/skill hashes and limitations. Missing fields remain null/unknown. Citation status describes stored citations, not a new validity assessment.

Imported batch linkage validates dataset/case/prompt hashes, target revision, policy revision, evaluation mode, batch and execution IDs against the stored report and snapshot. It uses imported internal IDs for linkage while preserving source testcase IDs for labels. Unsafe, duplicate or Windows-reserved filenames receive stable safe alternatives; their source labels remain in manifest/CSV. No external dataset assertions become verdicts.

## Deliberate disclosure limits

“Full” means all selected cases and all fields available through the existing sanitized reporting contract. It does **not** mean raw source reports:

- Original prompts are not exposed by this reporting contract. Exports contain `original_prompt: null` and an explicit omission reason; no dataset is reopened to recover prompts.
- Target responses remain sanitized previews (up to 4096 characters); preview redaction/truncation flags are preserved. Source completeness does not imply that the exported preview is full text.
- Judge explanations, citations and evidence details retain normalizer limits and redaction. Citations are not revalidated against altered previews.
- Credentials, Bearer/JWT/API-key patterns and local paths are filtered using existing reporting redaction plus a second export pass. Raw authentication headers and arbitrary nested log bodies are not included. Redaction is pattern-based, not a general guarantee that arbitrary unlabeled sensitive prose can be recognized. Review exports before external distribution.
- No unrelated archived assessments or Evidence Source captures are bundled. No export content is sent to an external Judge.

## Offline validation

Tests use synthetic reports, mock browser downloads and Flask's in-process test client. They cover 30-case membership, imported/native ID linkage, counts, Judge citations, hashes, redaction, CSV injection, unsafe names, missing reports, root authorization, cross-batch rejection, stale UI downloads and unchanged source bytes.

The existing ASI03 batch `08f8a0c76c394527bec964f8aed5b9db` was also exported in memory without any service/Target/Judge request. The recorded 30 reports must retain their pre-task aggregate SHA256:

`41a393e88a3e0052c59ca10c8b162de86e81f4abec2cf050d13476e7c4ce97d3`

Final checks for this implementation:

- Backend reporting/export/imported-workflow regression: **254 PASS**, including **16 export tests**.
- Full frontend suite: **165 PASS**; TypeScript/Vite build PASS.
- Browser: Results/Detail JSON download PASS; Batch ZIP download PASS. Edge closed before the second test on the first attempt; the isolated batch test subsequently passed without implementation changes.
- Existing ASI03 batch: **33 ZIP members**, exactly **30 reports TC0001–TC0030**, **30 CSV rows**, all member hashes valid; stored PASS count remains 30. Semantic invocation is reported true for 30; provider-invoked metadata is unknown for 30, not zero calls.
- Pattern scan found no credential/Bearer/JWT or local-path leaks in that in-memory ZIP. This is bounded pattern verification, not a guarantee about arbitrary unlabeled sensitive prose.
- All source run JSON files and batch state were byte-identical after export. Historical aggregate matches the digest above. The verification ZIP was not written to disk.

Files added: `backend/src/reporting/exports.py`, `backend/tests/test_report_exports.py`, `frontend/src/DownloadReport.tsx`, `frontend/src/DownloadReport.test.tsx`, `frontend/browser-tests/report-downloads.spec.ts`, and this document.

Files extended: `backend/src/reporting/api.py`, `frontend/src/BatchProgress.tsx`, `frontend/src/BatchProgress.test.tsx`, `frontend/src/Executions.tsx`, `frontend/src/ExecutionDetail.tsx`, `frontend/src/styles.css`. All pre-existing working-tree changes were retained.
