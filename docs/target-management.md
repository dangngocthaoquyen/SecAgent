# Operator target management

## Default local single-user mode

Run `python start_secagent_local.py` from the repository root after installing
the Python and frontend dependencies described in the README. One launcher
starts the loopback frontend, Workflow API and Reporting API, and prints the
frontend URL. It selects the user's local application data directory for the
managed catalog and a bounded controlled-run root under repository `results`.
It leaves other running services untouched by selecting free loopback ports.
Stop the launched services with Ctrl+C in the launcher terminal.

The launcher creates a random operator credential in memory and passes it to
the Workflow API and local frontend proxy. The proxy adds it only to the
existing privileged Workflow routes. The browser does not receive or enter the
credential. Direct Workflow API administration still requires authentication;
the frontend proxy enforces loopback host and same-origin requests, and the
Workflow API retains its origin and validation-nonce checks. This is a local
single-user trust model, not a remote multi-user authentication service.

In the frontend, add or edit a target, validate, and save. New or changed
targets are unreviewed. For a supported literal-IP endpoint, the first **Test
Connection** requires a confirmation showing the exact endpoint. That action
records the revision-bound target review and sends one bounded benign request.
Subsequent probes of the unchanged target do not repeat the confirmation.
If a safe probe is unsupported, the frontend instead offers an explicit
exact-endpoint authorization confirmation before test selection; it makes no
reachability or compatibility claim.
Execution still requires explicit per-run confirmation, a fresh plan, the
one-use GH-C01 grant and all existing admission checks. No Judge is enabled by
the local launcher; evaluation defaults to rule-only.

The **Discover from URL** option accepts an explicitly confirmed literal
loopback HTTP(S) URL and reads at most three fixed metadata documents. It
suggests a chat profile when the operator supplied a chat path or OpenAPI
advertises one. The operator can correct the suggestion before using the
existing validation, save and review steps. Discovery does not run a testcase,
approve a target or create an execution grant. See `docs/target-discovery.md`.

The older, explicitly configured authenticated mode remains available for a
future server deployment. In that mode, target management still requires the
operator secret and separate review controls described below.

## Explicit authenticated mode

SecAgent can store target profiles and review records in a local operator-owned
directory. The directory is selected at Workflow API startup and must be outside
the repository. Frontend requests never supply a filesystem path. The existing
catalog file supplies initial, **unreviewed** examples; later changes are saved
to `target-catalog.json` in the selected directory with an atomic replacement.
Restarting the Workflow API reloads that file. A changed startup policy or
credential binding rejects the stored catalog until the operator resolves it.

The Workflow API needs `SECAGENT_WORKFLOW_OPERATOR_TOKEN` in its environment,
with at least 32 characters. The token is not stored in target data. Start the
API with `--catalog configs/workflow/authorized-targets.example.json` and
`--target-data-dir` pointing to an operator-owned local directory. The example
already contains DVAA ResearchBot at `127.0.0.1:7015`, with `reviewed: false`.
The frontend can edit, validate, save and review it without changing that JSON.
Additional targets can be added with **Add Target**. Only HTTP OpenAI-compatible
chat with one configured model and the `chat` capability is supported by this
form. MCP and A2A are not implied by the catalog.

## Frontend workflow

1. Open **Targets**, enter the local operator secret and choose **Unlock target
   management**. The secret stays in page memory and is sent only in the
   operator header to the loopback Workflow API. **Lock** clears it.
2. Choose **Add Target** or **Edit Target**. The ResearchBot example fills DVAA,
   `http://127.0.0.1:7015/v1/chat/completions`, model `researchbot`, and 30
   seconds. Its endpoint port selects the DVAA agent; the model value does not.
3. Choose **Validate Target Details**, then **Save Configuration**. New and
   edited profiles are unreviewed. Editing a profile invalidates its previous
   review; security-relevant changes also change the profile revision and make
   old plans and grants inapplicable.
4. Review the exact endpoint, protocol, model, configured capability, policy
   and revision on screen. Confirm authorization and choose **Review / Approve
   Target**. The record is tied to that exact revision and policy. Review alone
   creates no execution grant.
5. For a reviewed literal-IP HTTP target, **Test Connection** sends one bounded
   benign chat request to the exact endpoint. It requests no tools, follows no
   redirect, uses no environment proxy, and returns only HTTP reachability,
   response-contract compatibility and a request count. A compatible response
   must contain `choices[0].message.content` as a string. The response text is
   not returned to the browser or saved as a security finding. A request failure
   makes reachability unknown; it is not a target security verdict.
6. Validate the selected target configuration and continue to ASI and testcase
   selection. The existing plan, admission and execution screens remain in use.

## Controlled execution prerequisite

Live execution remains disabled unless the Workflow API starts with the
existing `--enable-controlled-runs` flag, an explicit `--run-output-dir` below
the workspace results directory, and the operator secret. With target
management enabled and no admission policy file, startup uses the deny-all
`AdmissionPolicy`. The frontend can issue a ten-minute, one-use grant only for
the existing benign `GH-C01` slice, after target review, fresh plan preview,
asset and binding checks, and an explicit operator confirmation. The grant is
audited in the controlled-run output directory. Restarting the service does not
restore an unspent frontend-issued grant. A stale plan, changed target revision,
expired grant or claimed grant blocks dispatch. The dispatcher allowlist and
one-request budget are unchanged.

The reporting service still requires its separately selected controlled-runs
root to open a newly saved report. Hybrid Judge use still requires the existing
server-owned opt-in configuration. Neither target review nor a successful
connection probe enables either service.

## Administrative boundary

Management and probe requests require the separate operator secret. State
changes also require the existing same-origin check and validation nonce. The
Workflow API listens on loopback. Stored profile data contains identifiers,
endpoint, model, timeout, policy and review metadata, not credential values.
Credential aliases can only come from the operator's startup catalog. The
browser cannot choose a subprocess, provider, credential variable, execution
grant scope, response parser or arbitrary output path.
