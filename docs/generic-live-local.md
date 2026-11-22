# Generic imported testcases: Live Local handoff

Status: **implemented; awaiting human live acceptance**. Automated checks use
an in-process HTTP boundary. They have not contacted DVAA, AIGoat or CodeBot.

## Start and configure

From the repository root, with the existing Python and Node dependencies:

```powershell
python start_secagent_local.py --enable-custom-imported-batch --enable-imported-live-local
```

The launcher starts the Workflow API, Reporting API and frontend with an
internal local proxy credential. Both **Offline Mock** and **Live Local** are
available in the Dataset Library. No execution mode is chosen silently: the
browser sends the selected transport mode in both preview and submission,
and the server binds it into the plan hash and batch snapshot. The default
choice is Offline Mock. The launcher otherwise stays deny by default for
imported live execution.

In **Targets**, add an OpenAI-compatible chat profile using the operator's
complete endpoint URL, model and timeout. An example for the human's first
acceptance is `http://127.0.0.1:7004/v1/chat/completions` with model
`codebot`. Neither value is hardcoded into the execution binding. Save the
profile, confirm authorization for its exact endpoint, and click **Test
Connection**. This sends one benign message and checks the actual HTTP/JSON
contract. A successful check is valid for that profile revision and model
for ten minutes in the current Workflow API process. An edit changes the
revision and requires another review and connection check. A restart also
requires another connection check. Metadata discovery is separate, bounded
and advisory; advertised capabilities never authorize a run.

In **Datasets**, import the original JSON bytes, select one case initially,
select the reviewed target, then choose **Live Local**. Preview must show
one Ready case, a plan identity and a one-request budget. **Run Selected
Tests** is the per-run authorization confirmation. The backend creates a
single-use grant for each selected case and sends each prompt once through
the existing generic HTTP adapter and Native Runner. Batch Results and
**View Report** use the controlled-run Reporting API. Select more cases only
after the operator inspects the first report.

## Supported contract and safety boundary

Live Local accepts only an HTTP(S) URL with a **literal loopback IP** and
the exact `/v1/chat/completions` path, a reviewed managed profile using
`openai-chat`, no credential binding, and a successful recent compatibility
probe. A hostname, non-loopback destination, alternate path or protocol is
blocked. No broad internal network discovery or arbitrary JSON mapping is
supported. The request uses the configured model and one user message with
the exact imported prompt. It requests no tools. The bounded client uses
the exact reviewed URL, POST, no redirects, no environment proxy, one
request per case, configured timeout and a 64 KiB response cap. The
authorization plan binds target revision, dataset hashes, case hashes,
transport mode, request budget and connection check. Cancellation prevents
future dispatch; an in-flight request is not claimed to be remotely cancelled.

The report distinguishes transport delivery, captured response, and security
verdict. Imported prompts that exactly match the currently pinned native
GH-C01, GH-001 or GH-002 rendered input are bound to those native ASI01 goals,
rules and asset hashes at preview and again before dispatch. The operator sees
the selected binding in preview and confirms it at Run. GH-001 and GH-002
require GH-C01 earlier in the **same** batch and its persisted PASS before
either attack request is sent. Rule-only matching may produce PASS or FAIL
only from the native rule and a complete observed response. Ambiguous output
remains INCONCLUSIVE. If the server has explicitly enabled its existing
bounded Hybrid Pi Judge, Datasets offers Hybrid and preview blocks any case
without an exact pinned native input. The existing Judge request, citation validation and verdict resolver
apply. Missing or incomplete response text abstains before a Judge call for
this imported response-only mapping. The default local launcher remains
Rule-only and does not invoke Pi.

All other imported prompts still have no trusted security rules or independent
tool-effect observer; a successful response remains **INCONCLUSIVE**.
Transport errors remain **ERROR**. Imported source assertions are inert
metadata. Native reports retain dataset and prompt hashes, target identity,
revision, endpoint/model, transport mode, connection probe identity, actual
request count and evidence provenance. A live-local report says
`target_observation`; an Offline Mock report says `synthetic_mock`.
Neither provenance label attests to independent tool execution.

The operator's locally imported 30-case SearchBot dataset was inspected
read-only: zero prompts match the pinned native ASI01 inputs. Its source plugin
labels all 30 as `hijacking`, but source metadata is untrusted. Twenty-nine
prompts contain no absolute URL; one contains a URL, but no case is attached
to a fresh, correlated Web fixture or collector. None of these 30 can receive
an ASI01 security PASS or FAIL from the direct-chat binding. Cases claiming
indirect Web behavior require a separately reviewed adaptation of the
legitimate task, attacker-controlled page body and fixture/collector lifecycle.
Cases requiring phone calls, private profile access or other effects also need
appropriate independent observers and are unsupported by the current Web Lab
callback contract. This assessment does not rewrite their original bytes,
change historical verdicts or automatically import source assertions as rules.

An HTTP 200 response with `choices[0].message.content = null` has no text
preview. A reported `finish_reason: stop` does not establish that content was
present or that the response-only task completed. New native reports expose
the target-reported finish reason and assistant-content presence separately;
missing text or unknown completeness remains INCONCLUSIVE. The older reports
retain only their already saved observations and are not altered.

The existing native ASI01 and guarded Web Lab bindings are separate,
reviewed execution contracts. This generic imported mode does not unlock
their attack cases or ASI02/ASI03/ASI05 security verdicts. Non-OpenAI HTTP,
A2A, arbitrary MCP and credentialed live endpoints require a separate
validated adapter and authorization policy.
