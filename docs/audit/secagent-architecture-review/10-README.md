# 10 — SecAgent Architecture Audit Index & Methodology

> **Project:** SecAgent — AI-Agent-based Automated Penetration Testing Framework  
> **Vietnamese Thesis Title:** *“Xây dựng Framework tự động hóa Penetration Testing dựa trên AI Agent”*  
> **Repository Audited:** `D:\SecAgent-Integration`  
> **Git Revision:** `31614cac3c1e50f2f9c1edc764f064e05b76785f` (branch `Q/secagent-integration`)  
> **Audit Mode:** Strictly Read-Only Static Source Audit (zero source modifications, zero live LLM/target calls, zero Git mutations)

---

## 1. Document Index

| # | Document | Purpose & Audience |
|---|---|---|
| 01 | [01-SOURCE_INVENTORY.md](./01-SOURCE_INVENTORY.md) | Git revision, worktree state, exact first-party file counts (`620` files excl. `results/` & deps), verification of baseline paths (incl. `ScanResultsAndDrawer.tsx` split), DVAA vs. AIGoat footprint. |
| 02 | [02-SYSTEM_ARCHITECTURE.md](./02-SYSTEM_ARCHITECTURE.md) | Real deployed 3-process loopback topology vs. 7 logical subsystems (UI, Target Management, Generator, Execution Engine, Evidence Collection, Evaluation, Persistence & Reporting) with `Responsibility -> Inputs -> Processing -> Outputs -> Files -> Dependencies -> Persistence -> Failure cases`. |
| 03 | [03-END_TO_END_WORKFLOWS.md](./03-END_TO_END_WORKFLOWS.md) | Function-level traces of Workflows 1–6 (Target Onboarding, Application Context A–E & `stale`, AI Generate & Run, Existing Dataset, Stop/Cancel/Resume, Evaluation & Reporting + Binary `PASS` vs. `JUDGE_ERROR`). |
| 04 | [04-GENERATOR_AND_JUDGE.md](./04-GENERATOR_AND_JUDGE.md) | Deep dive into Generator G11 (limits, readiness, trusted skills, prompt-injection separation, DeepSeek HTTP provider, chunking, parsing, dedup) and Hybrid Judge G12/G14 (Pi CLI, rubrics, citation grounding, fault classification, Binary Policy v2.2.0). |
| 05 | [05-DATA_AND_EVIDENCE.md](./05-DATA_AND_EVIDENCE.md) | Canonical domain models, atomic JSON + RAM-only storage architecture, 5-level evidence provenance & strong correlation rules, SHA-256 redaction/hashing, read-only Reporting API integrity rules. |
| 06 | [06-SECURITY_AND_LIMITATIONS.md](./06-SECURITY_AND_LIMITATIONS.md) | Security trust boundaries, complete source-verified **ASI05 Case Study** (inline `steps`, `run_shell`, redaction, `NONZERO_EXIT`/HTTP 402), target generalization matrix, and clearly labeled **future external middleware design** for AIGoat ASI01. |
| 07 | [07-THESIS_WRITING_GUIDE_VI.md](./07-THESIS_WRITING_GUIDE_VI.md) | Academic Vietnamese thesis chapter guide, thesis-ready technical paragraphs, terminology table, threats to validity, and academic defense Q&A. |
| 08 | [08-TRACEABILITY_MATRIX.md](./08-TRACEABILITY_MATRIX.md) | End-to-end traceability matrix mapping every major architectural claim to entry points, core implementations, inventoried tests, `file:line` citations, and confidence level. |
| 09 | [09-AUDIT_FINDINGS.md](./09-AUDIT_FINDINGS.md) | Synthesized strengths, confirmed limitations, gaps/suspected defects (`F1–F8`), missing coverage, and prioritized P0/P1/P2 engineering recommendations. |
| 10 | [10-README.md](./10-README.md) | This master index, audit scope, methodology, and caveats. |

---

## 2. Mermaid Diagrams Index (`diagrams/`)

| # | Diagram File | Diagram Type | Focus |
|---|---|---|---|
| 1 | [01-overall-system-architecture.md](./diagrams/01-overall-system-architecture.md) | `flowchart TB` | Deployed 3-process loopback topology vs. logical subsystems, storage & external boundaries |
| 2 | [02-end-to-end-scan-flowchart.md](./diagrams/02-end-to-end-scan-flowchart.md) | `flowchart TD` | End-to-end security scan flow across AI Generate & Run, Generate Only, Existing/Import, Cancel & Resume |
| 3 | [03-testcase-execution-sequence.md](./diagrams/03-testcase-execution-sequence.md) | `sequenceDiagram` | Single real testcase lifecycle: Browser -> Vite Proxy -> Workflow API -> HTTP Adapter -> Target -> Evidence -> Hybrid Judge (Pi CLI) -> Atomic Disk |
| 4 | [04-generator-internal-workflow.md](./diagrams/04-generator-internal-workflow.md) | `flowchart TD` | Generator G11 internal pipeline: Readiness, Confirmed Context Snapshot, Bounded Chunking, Validation, Dedup, Mode 1 vs. Mode 2 |
| 5 | [05-evidence-and-verdict-decision-flow.md](./diagrams/05-evidence-and-verdict-decision-flow.md) | `flowchart TD` | Evidence verification levels, scope-family gates, Judge invocation, technical errors (`JUDGE_ERROR`/`EXECUTION_ERROR`), and Binary Policy v2.2.0 |
| 6 | [06-data-and-persistence-model.md](./diagrams/06-data-and-persistence-model.md) | `erDiagram` | Local atomic JSON files, SHA-256 lineage/provenance bindings, and RAM-only stores |

---

## 3. Audit Scope, Methodology & Caveats

- **In Scope:** All first-party Python backend (`backend/src/`), React/TypeScript frontend (`frontend/src/`), root launcher (`start_secagent_local.py`), trusted skill prompts (`generator_skills/`, `evaluator_skills/`), target/workflow configs (`configs/`), and static test inventory (`backend/tests/`, `frontend/src/*.test.*`, `frontend/browser-tests/`).
- **Out of Scope / Excluded:** Third-party dependency trees (`node_modules/`, `.venv/`), binary/cache directories (`__pycache__/`, `.pytest_cache/`, `dist/`), and historical execution artifacts under `results/` (preserved untouched, including pre-existing untracked `results/ASI02_L2_db_check.csv`).
- **Methodology:** Direct static code inspection, call-graph tracing across frontend API clients and Flask route handlers, schema/contract inspection, and automated static verification of cited file paths, line bounds, secret absence, and unmodified Git state.
- **Verification Caveat:** Because live penetration tests, paid LLM API calls (DeepSeek/OpenAI), external target probes (DVAA/AIGoat), service restarts, and test runner executions were strictly prohibited by the audit rules, **runtime execution behavior is verified statically from source code**, not from newly run live test executions in this session.
