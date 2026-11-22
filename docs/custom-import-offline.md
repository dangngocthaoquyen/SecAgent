# Custom JSON datasets: offline execution

B4.7 imports testcase definitions, not Promptfoo result reports. Source assertions,
plugins, transforms, variables and taxonomy are inert source claims. They never
select credentials, endpoints, Python functions or security verdicts.

## Start

From the repository root with the existing Python and frontend dependencies installed:

```powershell
python start_secagent_local.py --enable-custom-imported-batch
```

Optional isolated operator storage:

```powershell
python start_secagent_local.py --enable-custom-imported-batch --data-dir "$env:LOCALAPPDATA\SecAgent-B47"
```

The launcher prints the local browser URL. Open Targets and save/review a chat
profile (for example `http://127.0.0.1:17047/v1/chat/completions`, model `offline`).
This mode uses an in-process MockTransport for execution, connection checks and
discovery. No HTTP target, shell, tools, Promptfoo or LLM is invoked. Credentials
are unsupported and are rejected during preview. Other batch modes require a
separate session. Do not interpret the displayed endpoint as a live connection.

Open Dataset Library, upload the original JSON file, validate, confirm import,
select cases, select the reviewed target, inspect the request budget and start.
Starting explicitly authorizes that immutable selection. Use batch results to
open per-case Native Reports. Completed records survive refresh and restart.
An interrupted batch is not automatically resumed or replayed.

## Identity, storage and limits

The browser sends the original File bytes unchanged for both validation and import.
`file_sha256` and `dataset_revision_sha256` mean SHA-256 of those original bytes.
Identical bytes deduplicate, independently of filename/time. Different whitespace,
escaping or formatting creates a distinct dataset revision, even if JSON values
are equivalent. `content_sha256` is a separate deterministic digest of the
normalized immutable dataset, excluding display filename and import timestamp.

Original UTF-8 bytes are retained as base64 in a versioned record beside its
normalized envelope, under `<operator data>/targets/datasets` for the launcher.
Every load rehashes prompts and original bytes and reconstructs the normalized
record. Invalid records are not runnable and are omitted from listing. Existing
records are never replaced through import. Pre-remediation experimental records
without verifiable original bytes are unsupported; retain them and import original
sources using a fresh operator data directory. Historical execution reports remain
readable and are not migrated or rewritten.

Source IDs, nulls, descriptions, plugin labels and complete source testcase objects
are retained without trimming/truncation. Generated `import-…` internal IDs are used
for selections, grants and filenames, with an explicit source-ID mapping in the
dataset, batch and Native Report. Dataset IDs are mandatory; cross-dataset lookup
and source-ID fallback are forbidden.

Limits: 5 MiB UTF-8 JSON, 100 testcases, 64 KiB per prompt, 4096 characters per
source ID, 50 assertions per case and nesting depth 10. Duplicate IDs/object keys,
unsafe metadata keys, invalid Unicode/nonfinite numbers, non-object assertions,
and unsupported prompt shapes are rejected. Only literal `prompt` or `vars.prompt`
strings are supported; other variables and transforms are preserved, not rendered.
Source text is React-escaped. Only operator-owned local regular storage is supported;
symlinks/reparse points and network roots are rejected.

## Authorization, evidence and limitations

The trusted direct-chat binding uses the existing Native Runner, Executor,
HttpTargetAdapter, bounded HTTP client and BatchOrchestrator. It requires the exact
reviewed chat target/revision and the existing admission timeout ceiling. Each case
has a one-use grant and one request maximum; the batch budget is independently
enforced. Grants expire no later than ten minutes after batch authorization.
Retirement removes only grants owned by this workflow; the 20-entry policy capacity
is unchanged. An operator must release unrelated grants if they fill that capacity.

Cancellation gates transport immediately before dispatch and stops later cases.
An already-dispatched request cannot be recalled. Counts represent bounded transport
attempts, including transport failures; capture/completion and security verdict are
separate. Unexpected accounting failures remain explicitly unknown, never zero by
assumption.

Generic imported delivery is unclassified, not automatically ASI02. No reviewed
security evaluation or independent effect observer is available in this phase.
Successful transport yields INCONCLUSIVE with that explanation, including refusals,
action claims and the former dummy canary. Transport errors remain ERROR. Built-in
testcase rules are unchanged. No Judge is configured or called.

Native reports include source/internal IDs, original and normalized digests, prompt
hash, target revision, binding, submission, authorization, batch execution identity,
response provenance and actual request count. Report hashes, summary counts and
batch references are cross-checked. These digests detect inconsistent modification;
they are not signatures against an attacker able to rewrite every artifact and
digest in operator-owned storage. Response/prompt display remains subject to existing
report redaction; the original dataset bytes and prompt digest are authoritative.

An additional Live Local delivery mode is documented in
[`generic-live-local.md`](generic-live-local.md). It uses the same imported
dataset, native Runner and reports, but requires explicit startup opt-in,
an exact reviewed loopback chat target, a fresh compatible Test Connection and
per-run authorization. Neither mode establishes an ASI02 verdict without a
reviewed evaluation and independent action evidence.

The CodeBot source is `testcases_dvaa_codebot_asi02.json` paired with
`redteam (1).yaml` (30/30 prompts and assertions). `redteam.yaml` is the different
ResearchBot dataset and is not its source.
