# Diagram 6 — Data and Persistence Model (Mô hình dữ liệu và lưu trữ bền vững)

> **Gợi ý chú thích hình luận văn (VI):** *Hình X.6: Mô hình thực thể dữ liệu và liên kết băm SHA-256 (lineage & provenance) của SecAgent trên hệ thống tệp JSON cục bộ và kho bộ nhớ tạm (RAM-only).*

## Lưu ý kiến trúc lưu trữ thực tế

SecAgent **không sử dụng cơ sở dữ liệu quan hệ (RDBMS)** hay hệ quản trị hàng đợi (message broker). Toàn bộ trạng thái bền vững được ghi nguyên tử (write temp -> flush -> atomic replace) dưới dạng tệp JSON có kiểm chứng băm SHA-256 tại hai gốc thư mục chính (`<data_dir>` mặc định `%LOCALAPPDATA%\SecAgent` và `results/`), kết hợp với **3 kho chỉ lưu trên RAM** bị xóa khi khởi động lại tiến trình (`SessionCredentialStore`, `GeneratorPreviewStore`, `TargetExecutionLockRegistry`).

```mermaid
erDiagram
    MANAGED_TARGET ||--o| APPLICATION_CONTEXT : "binds target_revision"
    MANAGED_TARGET ||--o{ RESPONSE_POLICY : "target_id + category"
    MANAGED_TARGET ||--o{ EVIDENCE_SOURCE : "target_id + target_revision"
    MANAGED_TARGET ||--o| SESSION_CREDENTIAL_RAM : "optional session_auth.ref_id"
    MANAGED_TARGET ||--o{ GENERATE_AND_RUN_WORKFLOW : "target_id + target_revision"
    MANAGED_TARGET ||--o{ GENERIC_SCAN_RUN : "target_id + target_revision_sha256"

    APPLICATION_CONTEXT ||--o{ GENERATOR_PREVIEW_RAM : "application_context_revision_sha256"
    APPLICATION_CONTEXT ||--o{ GENERATE_AND_RUN_WORKFLOW : "context_snapshot_sha256"

    GENERATOR_PREVIEW_RAM ||--o| DATASET_ENVELOPE : "explicit save -> dataset_id"
    GENERATE_AND_RUN_WORKFLOW ||--o| DATASET_ENVELOPE : "auto-save -> dataset_id"
    GENERATE_AND_RUN_WORKFLOW ||--o{ GENERIC_SCAN_RUN : "workflow_id / run_id / rerun_history"

    DATASET_ENVELOPE ||--|{ IMPORTED_TESTCASE : "contains (1..100)"
    DATASET_ENVELOPE ||--o{ GENERIC_SCAN_RUN : "dataset_id + dataset_revision_sha256"

    GENERIC_SCAN_RUN ||--o{ GENERIC_SCAN_RUN : "continuation_of_run_id / root_run_id"
    GENERIC_SCAN_RUN ||--o| SUBMISSION_RECORD : "idempotent submission_id"
    GENERIC_SCAN_RUN ||--|{ NATIVE_CASE_REPORT : "per-case run_id + report_path"
    NATIVE_CASE_REPORT ||--|| CONTROLLED_RUN_SUMMARY : "report_sha256 verified"

    MANAGED_TARGET {
        string id PK "targets.json"
        string protocol "openai-chat | http-json | mcp-jsonrpc"
        string endpoint "canonical URL"
        string profile_revision "SHA-256 functional config"
        string authorization_status "review_required | reviewed_for_offline_configuration"
        string credential_alias "env alias or null"
        json http_config "body_template + response contract"
        json capability_states "supported | unsupported | unverified"
    }

    SESSION_CREDENTIAL_RAM {
        string ref_id PK "RAM-only sess_<24hex> (max 64)"
        string bound_origin "scheme://host:port"
        string scope_id "target_id / draft"
        string auth_type "bearer | api_key"
        string generation "32hex TOCTOU token"
    }

    APPLICATION_CONTEXT {
        string target_id PK "application-contexts/<target_id>.json"
        string target_revision "pinned profile_revision"
        string revision_sha256 "SHA-256 content"
        string provenance "operator_declared"
        json draft_18_fields "Sections A-E"
        json field_provenance "discovered_observed | suggested_unverified | operator_confirmed"
    }

    RESPONSE_POLICY {
        string policy_id PK "response-policies/<policy_id>.json"
        string target_id FK
        string category "ASI category name"
        string evaluation_scope "e.g. response_command_artifact"
        string review_status "draft | reviewed"
        string revision_sha256 "SHA-256 reviewed snapshot"
    }

    EVIDENCE_SOURCE {
        string id PK "evidence-sources/<id>.json"
        string target_id FK
        string endpoint "must match --evidence-policy allowlist"
        string semantics "always target_reported (unverified)"
        json mapping "items, event_id, correlation_id, tool..."
    }

    GENERATOR_PREVIEW_RAM {
        string preview_id PK "RAM-only TTL 30m (max 32)"
        string target_id FK
        string context_snapshot_sha256 "confirmed A-E hash"
        string status "active | saved | expired"
        json candidates "original vs effective prompt + hashes"
    }

    DATASET_ENVELOPE {
        string dataset_id PK "datasets/<32hex>.json (immutable)"
        string name "clean filename"
        string file_sha256 "original bytes SHA-256"
        string content_sha256 "canonical content SHA-256"
        string source_tool "secagent_generator | promptfoo_report | custom"
        int total_testcases "1..100"
    }

    IMPORTED_TESTCASE {
        string internal_id PK "import-<24hex>"
        string testcase_id "unique in dataset"
        string prompt "UTF-8 <= 65536 bytes"
        string prompt_sha256 "SHA-256 prompt"
        json metadata "asi_category, scope, origin, context_basis"
        json extra "optional stored_response for offline mode"
    }

    GENERATE_AND_RUN_WORKFLOW {
        string workflow_id PK "workflows/gnr-<32hex>.json"
        string status "running | completed | failed | blocked | partial_stopped | interrupted | cancelled"
        string current_stage "generating..reporting (7 stages)"
        string dataset_id FK
        string run_id FK
        json rerun_history "new run_id without regenerating"
    }

    GENERIC_SCAN_RUN {
        string generic_run_id PK "generic-runs/<32hex>/generic-run.json"
        string status "running | completed | failed | interrupted | cancelled"
        string mode "live | offline"
        string target_revision_sha256 "pinned target config"
        string dataset_revision_sha256 "pinned dataset file_sha256"
        string continuation_of_run_id FK "parent run for Resume"
        string root_run_id FK "logical scan lineage root"
        json evaluation_summary "Binary Policy v2.2.0 + technical_failure_count"
        json judge_metadata "provider, model, counts, faults"
    }

    SUBMISSION_RECORD {
        string submission_id PK "generic-runs/submissions/<32hex>.json"
        string generic_run_id FK
        string request_fingerprint "SHA-256 canonical request"
    }

    NATIVE_CASE_REPORT {
        string run_id PK "<generic_run_id>/<case>.secagent.json"
        string testcase_id "case_id"
        string target_id FK
        json evaluation "execution + observation + evidence_v2 + judge + final_result"
    }

    CONTROLLED_RUN_SUMMARY {
        string run_id PK "local-controlled-runs/<32hex>/run-summary.json"
        string generic_run_id FK
        string report_file "*.secagent.json"
        string report_sha256 "SHA-256 verified by Reporting API"
        int target_request_count "0 or 1"
    }
```

## Source References

- Managed Targets & Revisions: `backend/src/workflow/management.py:141-154, 533-637`
- RAM-Only Session Credentials: `backend/src/workflow/session_credentials.py:1-467`
- Application Context A-E: `backend/src/workflow/application_context.py:1-133`
- Response Policies & Evidence Sources: `backend/src/workflow/response_policies.py:1-435`, `backend/src/workflow/evidence_sources.py:1-374`
- Immutable Dataset Repository: `backend/src/workflow/dataset_repository.py:1-80`, `backend/src/workflow/dataset_normalizer.py:1-382`
- Generator Preview Store & Workflows: `backend/src/generator/preview_store.py:1-400`, `backend/src/generator/orchestrator.py:1100-1800`
- Generic Scan Runs, Submissions, Lineage & Controlled Run Summaries: `backend/src/workflow/routes_generic_runner.py:1799-2255, 2617-2741, 3987-4347`
- Reporting API Verification of Controlled Runs: `backend/src/reporting/repository.py:63-203`
