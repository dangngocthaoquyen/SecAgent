# Diagram 3 — Single Testcase Execution Lifecycle Sequence (Biểu đồ tuần tự vòng đời một testcase)

> **Gợi ý chú thích hình luận văn (VI):** *Hình X.3: Biểu đồ tuần tự thực thi một testcase thực tế từ giao diện người dùng qua Vite Proxy, Workflow API, Target Adapter (HTTP JSON), bộ thu thập bằng chứng, bộ đánh giá lai (Hybrid Evaluator + Pi CLI Judge) đến khi lưu kết quả nguyên tử trên đĩa.*

```mermaid
sequenceDiagram
    autonumber
    actor Op as Operator (Browser UI)
    participant Proxy as Vite Loopback Proxy (:5173)
    participant API as Workflow API / GenericRunService (:8092)
    participant Runner as generic_runner & TargetRunner
    participant Adapter as HttpTargetAdapter
    participant Target as Target AI Agent (HTTP JSON)
    participant Collector as Evidence Collectors & Evidence v2
    participant Eval as HybridEvaluator & VerdictResolver
    participant Pi as Pi CLI Subprocess (LLM Judge)
    participant Disk as Atomic Local Storage (JSON)

    Op->>Proxy: POST /api/testing/generic-runs/start (submission_id, expected_target_revision, authorization_confirmed=true)
    Proxy->>API: Forward + inject X-SecAgent-Operator & verify X-SecAgent-Validation nonce
    API->>API: Validate target revision, session credential generation, acquire TargetExecutionLockRegistry
    API->>Disk: Write initial generic-run.json (status="running") + submissions/<submission_id>.json
    API-->>Op: HTTP 202 Accepted (generic_run_id, status="running")

    Note over API,Runner: Background worker thread (_execute_worker) executes sequentially per testcase

    API->>Runner: run_generic_cases(target, pairs, eval_cfg, provider, collectors, cancel_event)
    Runner->>API: _on_progress(stage="sending_request_to_target")
    API->>Disk: Atomic pre-dispatch checkpoint (generic-run.json)

    Runner->>Adapter: execute(target, test_input)
    Note over Adapter: Render body_template ({{input}}), resolve env/session credential headers in RAM
    Adapter->>Target: POST <target_endpoint> (JSON body, bounded timeout, no redirects)
    Target-->>Adapter: HTTP 200 JSON (answer, status, run_id, inline steps[])
    Adapter->>Adapter: extract_configured_http_response_context()\nHash arguments/observation -> SHA-256, mark inline events target_reported (execution_verified=False)
    Adapter-->>Runner: ExecutionResult(success=True, output_text, events[])

    Runner->>Collector: ResponseObserver.observe() + collect_target_evidence(collectors, CollectorContext)
    Collector->>Collector: Correlate IDs, enforce provenance tiers (never promote target_reported), build Evidence v2
    Collector-->>Runner: Observation(response_text, response_complete, evidence[]) + collector_diagnostics[]

    Runner->>Eval: HybridEvaluator.evaluate(testcase, observation)
    Eval->>Eval: 1) ResponseEvaluator (deterministic reviewed rules)\n2) EvidenceV2Evaluator (scope_family + verified execution gate)
    alt Semantic Judge Eligible (response_complete=True, scope allows semantic, budget > 0)
        Eval->>Eval: EvaluationRequestBuilder.build()\nSanitize/allowlist evidence + load trusted evaluator_skills/*.md (SHA-256)
        Eval->>Pi: Spawn pi --mode text --no-session --no-tools\nStdin: system skill + canonical JSON EvaluationRequest
        Pi-->>Eval: Stdout: strict JSON v1.0 (verdict, classification, reason, confidence, evidence citations)
        Eval->>Eval: parse_judge_response() (validate labels, exact span/ref citations)\nRetry only on TIMEOUT/PROCESS_ERROR/INVALID_OUTPUT
    else Execution Scope Missing Verified Evidence OR Judge Disabled/Faulted
        Note over Eval: Skip Judge or record ProviderFault (e.g. NONZERO_EXIT)
    end
    Eval->>Eval: VerdictResolver + classify_binary_case_outcome()\nProduce Binary verdict (PASS/FAIL) + evaluation_status + evidence_limitations
    Eval-->>Runner: EvaluationResult + JudgeDiagnostic + research_provenance

    Runner->>Disk: Write <case_run_id>/<case>.secagent.json (atomic)
    Runner->>API: _on_progress(event="case_completed")
    API->>Disk: Write local-controlled-runs/<case_run_id>/run-summary.json (with report_sha256)
    API->>Disk: Atomic update generic-run.json (verdict_counts, evaluation_summary, case_statuses)

    loop UI Polling (every 350ms until terminal status)
        Op->>Proxy: GET /api/testing/generic-runs/<generic_run_id>
        Proxy->>API: Forward GET
        API-->>Op: Updated GenericRunRecord (progress, cases, verdicts, technical failures)
    end

    API->>API: _verify_completion_invariants() & release TargetExecutionLockRegistry
    API->>Disk: Atomic write terminal generic-run.json (status="completed")
```

## Source References

- Frontend Start & Poll: `frontend/src/SecurityScanWizard.tsx:505-566, 875-982`
- Proxy Boundary: `frontend/vite.config.ts:40-115`
- Start Run, Pre-Dispatch Checkpoint, Progress & Invariants: `backend/src/workflow/routes_generic_runner.py:2028-3110`
- Generic Runner & Target Runner: `backend/src/testing/generic_runner.py:1000-1446`, `backend/src/testing/runner.py:1-350`
- HTTP Adapter & Inline Evidence Redaction/Hashing: `backend/src/targets/adapters/http_adapter.py:45-396`, `backend/src/targets/adapters/http_evidence.py:204-319`
- Collectors & Evidence v2: `backend/src/observers/evidence_collectors.py:805-1271`, `backend/src/core/evidence_v2.py:1-500`
- Hybrid Judge, Pi CLI & Binary Verdict Classification: `backend/src/evaluators/hybrid_evaluator.py:1-536`, `backend/src/evaluators/evaluation_request_builder.py:1-264`, `backend/src/integrations/external_evaluator/pi.py:1-325`, `backend/src/integrations/external_evaluator/validation.py:1-101`, `backend/src/evaluators/verdict_outcome.py:314-611`
