# 01 — Source Inventory & Git State

> **Audit Classification:** Confirmed source inventory (static read-only inspection).  
> **Repository Root:** `D:\SecAgent-Integration`  
> **Audit Date:** 2026-11-27

## 1. Git Revision and Worktree State

| Property | Verified Value |
|---|---|
| Active Branch | `Q/secagent-integration` |
| HEAD Commit | `31614cac3c1e50f2f9c1edc764f064e05b76785f` |
| Tracked Worktree Modifications | **None** (clean tracked worktree prior to creating audit docs) |
| Existing Untracked Files (Preserved) | `results/ASI02_L2_db_check.csv` |

### Recent 10 Commits (Architectural Evolution on `HEAD`)

1. `31614ca` — Bounded multi-chunk generator + safe cancel (`generator/service.py`, `generator/orchestrator.py`).
2. `b5fac40` — Flexible per-ASI counts up to 50 (`generator/constants.py`, `frontend/src/GeneratorConfigForm.tsx`).
3. `48f35b7` — Unified scan cancellation & safe resume (`routes_generic_runner.py`, `SecurityScanWizard.tsx`).
4. `dc27a17` — Canonical execution safety & shared target locking (`workflow/target_locks.py`, `workflow/api.py`).
5. `9c7c356` — R11 conditional policy matching & verdict provenance (`evaluators/verdict_resolver.py`).
6. `446dcd9` — G14 observation-based binary security verdicts (`evaluators/verdict_outcome.py`).
7. `7acc51c` — G13 unified security scan workflow (`frontend/src/SecurityScanWizard.tsx`).
8. `490c635` — ASI02 observation-based binary verdicts (`evaluators/verdict_resolver.py`).
9. `08bc77a` — Judge evidence & policy hardening (`evaluators/evaluation_request_builder.py`, `observers/evidence_collectors.py`).
10. `b8be904` — Merge G11 Generator with G12 Judge.

> **Important Historical Caveat:** The repository contains an older audit file `docs/audits/SECAGENT_CURRENT_ARCHITECTURE_AUDIT.md` (dated `2026-11-22`, originally written for `D:\SecAgent-W5-Judge` prior to G08/G10/G11/G12/G13/G14/G15). That document is **obsolete** relative to the current `HEAD` and was not trusted as ground truth.

---

## 2. First-Party Repository Inventory (Excluding Dependencies & Runtime Artifacts)

Static file enumeration excluded `node_modules/`, `.venv/`, `.git/`, `__pycache__/`, `.pytest_cache/`, `dist/`, `coverage/`, and runtime outputs under `results/`.

**Total First-Party Repository Files (excluding `results/` and dependencies): `620`**

| Directory / Subpackage | File Count | Role |
|---|---:|---|
| `<root>` | 5 | `start_secagent_local.py`, `README.md`, `pyproject.toml`, `CODEX_CONTEXT.md`, `.gitignore` |
| `.github/` | 1 | CI workflow configuration |
| `backend/requirements*.txt` | 3 | Python dependencies (`httpx`, `pydantic`, `PyYAML`, `Flask`, `pytest`) |
| `backend/src/workflow/` | 31 | Flask Workflow API, Target Management, Discovery, Context A-E, Datasets, Policies, Evidence Sources, Generic Runner, Shared Locks, Session Credentials |
| `backend/src/evaluators/` | 24 | Hybrid Evaluator, Deterministic Rules, Evidence v2 Evaluator, ASI05 Execution Core, Verdict Resolver, Observation-Based Binary Policy v2.2.0, Request Builder |
| `backend/src/generator/` | 21 | G11 Generator Readiness, Skills Loader, Request Builder, DeepSeek HTTP Provider, Parser, Validation, Deduplication, Bounded Multi-Chunk Service, Preview Store, Generate & Run Orchestrator |
| `backend/src/targets/` | 18 | HTTP JSON Adapter, Inline Evidence Extractor, MCP JSON-RPC Adapter, Hosted MCP Agent Runtime, DVAA Discovery & Action Observer, Target Validator |
| `backend/src/attack_modules/` | 17 | Legacy/modular OWASP ASI attack definitions and builders |
| `backend/src/core/` | 17 | Canonical Pydantic models (`TargetProfile`, `TestCase`, `TestInput`, `ExecutionResult`, `Observation`, `Evidence`, `EvaluationResult`) and `evidence_v2.py` |
| `backend/src/integrations/` | 13 | External Evaluator Provider interface, Pi CLI Subprocess Provider, Skill Bundle Loader, Judge JSON v1.0 Validator |
| `backend/src/reporting/` | 12 | Read-only Flask Reporting API (`:8091`), Report Normalizers, Controlled Run Integrity Loader, Aggregation, Redaction, Exports |
| `backend/src/testing/` | 12 | Generic Runner (`generic_runner.py`), Core Target Runner (`runner.py`), `RunnerEvaluationConfig` & `BudgetedJudgeProvider`, Offline Stored Importers |
| `backend/src/observers/` | 11 | `ResponseObserver`, Scoped Evidence Collectors (`SandboxLogFileCollector`, `FileArtifactCollector`, `HttpCallbackCollector`), DVAA MCP Execution Observer & Receipt Collector |
| `backend/src/payloads/` | 3 | Static payload helpers |
| `backend/src/tools/` | 3 | Bounded `HttpClient` wrapper |
| `backend/scripts/` | 20 | CLI & research utilities |
| `backend/tests/` | 172 | Pytest unit, integration, contract, and offline regression suites |
| `frontend/src/` | 74 | React 19 + TypeScript SPA components, typed API clients, formatters, Vitest unit tests |
| `frontend/browser-tests/` | 24 | Playwright end-to-end browser specifications |
| `frontend/` (root config) | 9 | `package.json`, `vite.config.ts`, `tsconfig.json`, `playwright.config.ts`, `index.html`, etc. |
| `generator_skills/` | 7 | Trusted Generator system prompts & per-ASI profiles (`ASI01`, `ASI02`, `ASI03`, `ASI05`) |
| `evaluator_skills/` | 10 | Trusted Judge system prompts, verdict policy, untrusted-content policy, vulnerability rubrics |
| `configs/` | 15 | DVAA target YAML profiles, example workflow catalogs, sample response policies, MCP action/agent configs |
| `deploy/` | 11 | Container/deployment support files |
| `design-reference/` | 20 | UI/UX design references |
| `docs/` | 67 | Existing specs, gate notes, and legacy architecture audit |
| **Total** | **620** | **100% first-party (excluding `results/` runtime outputs)** |

*(Runtime output directory `results/` contains `evaluation/`, `generic-runs/`, `local-controlled-runs/`, `smoke/`, and untracked `ASI02_L2_db_check.csv`.)*

---

## 3. Verification of Prompt-Listed Baseline Files

Every path listed in the audit brief was checked against the live filesystem:

| Prompt Path | Exists? | Status / Actual Path in Current `HEAD` |
|---|---|---|
| `start_secagent_local.py` | Yes | Local 3-process (+optional bridge) launcher (`L1-353`) |
| `backend/src/workflow/api.py` | Yes | Main Workflow Flask app & shared service composition (`L1-867`) |
| `backend/src/workflow/catalog.py` | Yes | Target presets, loopback/private-IP validation, `make_profile` (`L1-379`) |
| `backend/src/workflow/management.py` | Yes | `ManagedTargetCatalog`, dedup, revisions, review, deletion (`L1-1262`) |
| `backend/src/workflow/routes_targets.py` | Yes | Targets, Discovery, Probe, Session Auth, Context A-E, Evidence Sources routes (`L1-1071`) |
| `backend/src/workflow/routes_generic_runner.py` | Yes | `GenericRunService`, Preview, Start, Cancel, Resume, Unified Lineage (`L1-5359`) |
| `backend/src/workflow/evidence_sources.py` | Yes | Allowlisted read-only HTTP JSON evidence sources (`L1-374`) |
| `backend/src/workflow/models.py` | Yes | `Preset`, `HttpContractConfig`, `HttpResponseContract`, `HttpInlineEvidenceMapping` (`L1-320`) |
| `backend/src/generator/readiness.py` | Yes | Target/Context A-E/Scope/Policy readiness & snapshot builder (`L1-990`) |
| `backend/src/evaluators/contract.py` | Yes | Canonical scopes, capabilities, compatibility matrix (`L1-745`) |
| `backend/src/integrations/external_evaluator/pi.py` | Yes | Pi CLI subprocess wrapper & stderr fault classification (`L1-325`) |
| `frontend/src/TargetManager.tsx` | Yes | Target onboarding, headers/auth, probe diagnostics, capabilities (`L1-1655`) |
| `frontend/src/GeneratorConfigForm.tsx` | Yes | Shared Generator config form (`L1-414`) |
| `frontend/src/SecurityScanWizard.tsx` | Yes | Unified 3-step scan wizard, polling, stop/cancel, resume (`L1-1842`) |
| `frontend/src/EvidenceSources.tsx` | Yes | Evidence source CRUD & manual snapshot UI (`L1-80`) |
| `frontend/src/ScanResultsAndDrawer.tsx` | **No** | **Split into two components:** `frontend/src/ScanResultsView.tsx` (`L1-979`) and `frontend/src/TestcaseDetailDrawer.tsx` (`L1-659`). Only the unit test retains the name `frontend/src/ScanResultsAndDrawer.test.tsx`. |
| `frontend/src/testingApi.ts` | Yes | Workflow API typed client & runtime contract validators (`L1-519`) |
| `frontend/src/generatorApi.ts` | Yes | Generator & Generate-and-Run typed client (`L1-1100`) |

---

## 4. Runtime Dependencies & Technology Stack

- **Backend Python (`backend/requirements.txt`, `requirements-reporting.txt`, `requirements-dev.txt`):**
  - Web framework: `Flask >= 3.1, < 4.0` (both Workflow API and Reporting API).
  - HTTP client: `httpx >= 0.27, < 1.0`.
  - Schema validation: `pydantic >= 2.0, < 3.0`.
  - Config parsing: `PyYAML >= 6.0, < 7.0`.
  - Testing: `pytest >= 8.0, < 10.0`.
  - **Confirmed absent:** No SQLAlchemy/SQLite/PostgreSQL driver, no Celery/Redis/RabbitMQ, no LangChain/LangGraph runtime in SecAgent itself.
- **Frontend (`frontend/package.json`):**
  - `React 19.2.4`, `TypeScript 5.9.3`, `Vite 7.3.1`.
  - Testing: `Vitest 4.0.18` (unit/component), `Playwright 1.58.2` (E2E browser).
- **External CLI/APIs:**
  - Generator LLM: Direct HTTPS calls to DeepSeek Chat Completions API (`backend/src/generator/providers/deepseek_http.py`).
  - Judge LLM: Local `pi` CLI subprocess (`backend/src/integrations/external_evaluator/pi.py`).

---

## 5. Target Integration Footprint (DVAA vs. AIGoat)

- **DVAA (Explicit Lab Integration Present):**
  - Static target profiles: `configs/targets/dvaa.yaml`, `dvaa-legacybot.yaml`, `dvaa-ragbot.yaml`, `dvaa-securebot.yaml`, `dvaa-toolbot.yaml`, plus `configs/workflow/authorized-targets.example.json` and `authorized-targets.dvaa-multibot.draft.json`.
  - MCP action/agent configs: `configs/mcp_actions/dvaa_toolbot_canary.json`, `configs/mcp_agents/dvaa_toolbot_hosted_catalog.json`.
  - Dedicated lab helper modules: `backend/src/targets/adapters/dvaa_discovery.py` (port hints `7004`/`7010` and dashboard `:9000` unverified evidence suggestions), `backend/src/targets/adapters/dvaa_action_evidence.py`, `backend/src/observers/dvaa_mcp_execution_observer.py`, `backend/src/observers/dvaa_instrumented_receipt_collector.py`.
- **AIGoat (Zero Hardcoded Production Integration):**
  - Global repository grep confirms **zero references to AIGoat in `backend/src/`, `frontend/src/` production components, or `configs/`**.
  - AIGoat appears **exclusively in offline pytest fixtures** (`test_g10_1c_http_target_onboarding.py`, `test_g10_2_interrupted_scan_resume.py`, `test_g11_generator_skills.py`, `test_g14_strict_binary_evaluation.py`) as an example of a generic `http-json` target onboarded via the universal HTTP contract.
