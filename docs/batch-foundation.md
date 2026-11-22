# Offline batch execution foundation

`workflow.batch.BatchOrchestrator` is a trusted in-process, sequential coordinator. Phase B2 connects it to authenticated, mock-only routes through `workflow.offline_batch`; see [offline-batch-api.md](offline-batch-api.md). It does not bind a live testcase. The current web dispatcher and `AdmissionPolicy` retain the GH-C01 one-case live limit.

## Contract

The caller builds a frozen `BatchPlan` from server-validated target identity, exact profile revision and policy, ordered case IDs, asset hashes, input hashes, evaluation mode, and request budgets. A new batch gets an exclusive directory claim and `batch_run_id`. A root-level exclusive claim prevents concurrent batches sharing the output root; an interrupted process leaves it fail-closed for operator recovery. State is written atomically after each stage and case. Refreshing clients can read `state(batch_run_id)` without resubmitting work.

For each case the caller supplies a trusted admission decision and an executor callback. Admission is checked immediately before dispatch. The callback should invoke the existing native Runner with server-owned bindings, bounded transport, evaluation configuration and report writer. The orchestrator does not parse imported testcase code, issue grants, or perform network I/O. The executor must independently cap requests. Returned request counts are checked against each case's reserved budget. If the callback faults after an unknown amount of I/O, the full case budget is consumed, actual request count is marked unknown, and the case is recorded as an execution ERROR rather than a security FAIL.

Each case record has a distinct `execution_id`, execution status, optional security verdict, request count, and optional native report ID and SHA-256. Blocked, unsupported, skipped, and cancelled cases have no security verdict. A cancellation marker prevents the next dispatch after the active case finishes; it records the case active at the moment of cancellation. The active remote request is not claimed to be cancelled. Previously completed records remain in durable state. Progress is based on processed cases, not elapsed time. Stage events contain only a timestamp, fixed stage identifier, and testcase ID.

## Required integration before browser batch execution

1. Extend server-side selection and admission from one case to a reviewed batch policy, with case-specific bindings, evidence prerequisites, scoped authorizations and total budgets. Preserve the GH-C01-only live dispatcher until additional runtime contracts are verified.
2. Connect a trusted per-case native Runner executor and report writer. Count attempted requests at the bounded transport boundary, including faults.
3. Extend the existing mock-only batch submission, read-only progress and cancellation routes to production only after case-specific bindings and operator policies are verified. Stage events must come from actual Runner and transport boundaries; never infer Judge activity.
4. Add multi-select/suite UI and progress/results view. The current one-click frontend remains single-case.
5. Validate custom testcase definitions and suite persistence separately before allowing them into admission. Built-in assets remain immutable.

The offline tests in `backend/tests/test_batch_orchestrator.py` exercise the native Runner through a synthetic callback, without a target endpoint or Judge process. This proves the coordinator's state and accounting behavior, not multi-case web or live execution readiness.
