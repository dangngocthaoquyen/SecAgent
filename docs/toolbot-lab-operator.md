# Offline ToolBot Lab operator runbook

This workflow verifies SecAgent's product integration with the **unchanged
native TM-002 testcase** and a controlled synthetic ToolBot-compatible
handler. It does not contact DVAA, run a shell, or prove a live target finding.

1. Install the repository's Python and frontend dependencies as described in
   the local startup guide. Start a fresh local session from the repository:
   `python start_secagent_local.py --enable-toolbot-lab-batch`.
2. Open the printed local SecAgent URL. In Target Management choose **Add
   Target → Use offline ToolBot Lab example**. Validate, save and review the
   exact revision after confirming authorization. This records a target review;
   it does not enable any other MCP endpoint.
3. Validate the target configuration. Continue to testcase selection, select
   ASI02 and TM-002. TM-001 remains unsupported. Preview shows one ready case
   and a one-request budget. Select **Run Selected Tests** once.
4. Follow the batch progress and **View Report**. The expected synthetic
   handler effect can produce a native FAIL under TM-002's existing rule.
   Confirm the report says `synthetic_mock` and distinguishes `tool_request`,
   `target_tool_result`, `tool_call` and `tool_trace`.
5. Refresh the batch and individual report pages to verify persistence.

The endpoint `http://127.0.0.1:17022/mcp` is an exact profile identity used
inside the offline mock transport; SecAgent does not start a listener there.
Do not point this profile at the normal DVAA ToolBot or treat its report as
live security evidence. A later live acceptance requires a separate guarded
runtime, handler instrumentation, observation review and authorization.
