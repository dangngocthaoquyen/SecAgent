# Imported ASI05 response-command demo

This scope is `response_command_artifact`. It evaluates the assistant's complete
visible response for an agent-issued command artifact forbidden by a reviewed
target policy. It does **not** verify tool use, shell execution, effects, or RCE.
Native UCE-001/002/003 retain their independent action-evidence contracts and
are not made live-executable by this imported response path. Promptfoo grades
and empty `toolCalls` metadata are untrusted source data.

## Startup

Use the existing nonsecret operator-owned Judge configuration described in
[asi03-response-evaluation.md](asi03-response-evaluation.md), with the provider
credential already set in the shell. The launcher gives every selected testcase
a fresh Runner and a maximum of one Judge call. A 30-case batch can therefore
make up to 30 sequential target requests and 30 separate Judge calls.

```powershell
cd D:\SecAgent-W5-Judge
python .\start_secagent_local.py --enable-custom-imported-batch --enable-imported-live-local --judge-config "$env:LOCALAPPDATA\SecAgent\asi03-judge.json"
```

## Operator workflow

1. In Targets, add or select the operator-owned local CodeBot OpenAI-compatible
   chat endpoint. Save and explicitly review its exact current profile revision.
   Use Test Connection with operator confirmation. A reviewed profile alone is
   not a verified connection. No CodeBot endpoint is hardcoded by this workflow.
2. In Datasets, import or select the original JSON dataset. Select **ASI05
   response command artifacts (no execution proof)**, then choose CodeBot.
3. Review one target response policy: prohibited agent-issued command behavior,
   permitted benign command context, and expected response boundary. Save the
   draft and explicitly review it. This policy is tied to the target revision,
   not to exact testcase IDs or Promptfoo labels.
4. Select 1, 5, or all 30 cases. Choose Live Local and Hybrid Judge. Preview the
   exact target, ready cases, and one-request-per-case budget. Run the selected
   batch once and monitor progress. Open each Native Report from Batch Results.
5. In a report, check the imported prompt and SHA-256, target and policy
   revisions, `response_command_artifact` scope, complete response observation,
   exact Judge citation, provider fault if any, final verdict, and actual request
   count. A response-level FAIL means a prohibited visible artifact was emitted;
   it is not proof of execution.

The first real CodeBot and Pi calls belong to the human operator's acceptance.
Offline fake-target and fake-Judge tests establish only pipeline behavior. If
the target is unreachable, the model is wrong, the response is incomplete, or
the Judge is unavailable, retain the specific error or INCONCLUSIVE result.
