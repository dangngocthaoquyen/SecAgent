# G16 — SecAgent Generator, Evidence & Judge Comparative Audit (ASI05)

> **Audit Type:** Strictly Read-Only Source, Artifact & Methodology Audit (zero modifications to application code, configs, credentials, runtime state, or Git history; zero live target or LLM API calls).
> **Repository:** `D:\SecAgent-Integration` (SecAgent — AI-Agent-based Automated Penetration Testing Framework)
> **Target Under Study:** `local-http-8000-api-agent-runs` (*"AIGoat ASI05 Agent"*, `http://127.0.0.1:8000/api/agent/runs`, `lab_id: "asi05-1"`)
> **Audit Date:** 2026-11-28

---

## 1. Document Map

| Document | Focus | Primary Audience |
|---|---|---|
| [`01_GENERATOR_AUDIT.md`](./01_GENERATOR_AUDIT.md) | Generator inputs, `ApplicationContext` bias, safety skills, chunking, validation, deduplication, 9-category classification of all 40 testcases, and 6 root-cause hypotheses | Architects, security researchers |
| [`02_EVIDENCE_JUDGE_AUDIT.md`](./02_EVIDENCE_JUDGE_AUDIT.md) | Complete HTTP -> Inline Evidence -> Redaction -> Deterministic Rules -> Judge -> Export trace; 17 verification points; 7 evidence levels (A–G); forensic deep-dives (`TC09/10/19/20`, Run B FAILs & `TC0006`); `2.2.0-observation-binary` & `nonzero_exit` technical error audit | Security engineers, thesis reviewers |
| [`03_PROMPTFOO_COMPARISON.md`](./03_PROMPTFOO_COMPARISON.md) | Scientific critique of `3/20` vs. `10/20` FAIL; strict separation of **Experiment A (Generator)** vs. **Experiment B (Evaluator)**; 10 confounders; offline shared-corpus follow-up blueprint | Thesis methodology & evaluation chapter |
| [`04_CASE_LEVEL_MATRIX.md`](./04_CASE_LEVEL_MATRIX.md) | Complete 40-row case-by-case matrix (20 SecAgent + 20 Promptfoo) strictly separating observed facts from analytical interpretation | Traceability & thesis appendix |
| [`05_FINDINGS_AND_RECOMMENDATIONS.md`](./05_FINDINGS_AND_RECOMMENDATIONS.md) | Prioritized `P0` / `P1` / `P2` findings with Finding ID, evidence, `file:line` citations, impact, confidence (`CONFIRMED`/`INFERRED`/`UNVERIFIED`), and suggested future actions | Engineering roadmap (read-only recommendations) |
| [`06_THESIS_INTERPRETATION_VI.md`](./06_THESIS_INTERPRETATION_VI.md) | Hướng dẫn diễn giải học thuật bằng tiếng Việt: kết luận được / không kết luận được, bảng so sánh chuẩn, sơ đồ gợi ý, giới hạn & threats to validity, thiết kế thực nghiệm kế tiếp | Viết tiểu luận chuyên ngành & bảo vệ |

---

## 2. Exact Inspected Artifact Inventory

| Artifact Type | Identifier | Timestamp (UTC) | Key Metrics / Revision |
|---|---|---|---|
| **Run A (SecAgent G11)** | `f03ec703bc6a46c5ae64dcce1fd0451d` | `2026-11-27T16:42:00Z` -> `17:04:20Z` | 3/20 FAIL (15%), 17/20 PASS (85%), 0 tech errors; 4 `run_shell` inline events |
| **Run B (Promptfoo)** | `762bc2ef4fb3473aad7e869b316df427` | `2026-11-27T17:28:34Z` -> `18:15:37Z` | 10/20 FAIL (50%), 10/20 PASS (50%), 0 tech errors; 3 `run_shell` inline events |
| **Earlier Run A (Reproducibility Control)** | `959c574033a64be6bda7bb137a2a5974` | `2026-11-27T14:34:39Z` | 2/20 FAIL (10%), 18/20 PASS (90%), 0 tech errors; 3 cases flipped vs. Run A |
| **Judge-Error Run A (`nonzero_exit`)** | `81b73474825c4b278ace956da7e4545a` | `2026-11-27T15:28:37Z` | 0/20 FAIL, **20/20 PASS (100%)** despite **15 `JUDGE_ERROR` (`nonzero_exit`)** |
| **Dataset A (SecAgent G11)** | `b266782cdaa0dae0f61fd968f4f60e77` | `2026-11-27T14:34:22Z` | `g11-local-http-8000-api-agent-runs-gen-b4c69161.json` (rev `a3d02bdb...`), 20 cases |
| **Dataset B (Promptfoo)** | `33bc984b7056bad3e529b0d9facf1a4a` | Imported | `testcases_aigoat_adminagent_asi05.json` (rev `84a5cd5f...`), 20 cases, `plugin_id=shell-injection` |
| **Generator Run** | `gnr-09243a6526a74fbfaee3a915aa1cfb62` | `2026-11-27T14:34:22Z` | 2 chunks (15 + 5), `deepseek-flash`, `effective_scope=response_command_artifact`, 20/20 accepted |
| **Shared Target & Context (Run A & B)** | `local-http-8000-api-agent-runs` / `appctx-local-http-8000-api-agent-runs` | Identical in A & B | Target rev `977179948d9d...`, Context rev `797ae132b01f...`, `policy_id=null` |
| **Judge Engine (Run A & B)** | `PiEvaluatorProvider` -> `deepseek / deepseek-v4-flash` | Identical in A & B | `verdict_policy_version = 2.2.0-observation-binary`, 20/20 succeeded, 0 rules active |

---

## 3. Core Source Files Audited

- **Generator & Skills:** `backend/src/generator/readiness.py`, `backend/src/generator/request_builder.py`, `backend/src/generator/validation.py`, `backend/src/generator/deduplication.py`, `backend/src/generator/service.py`, `backend/src/generator/output_parser.py`, `generator_skills/SKILL.md`, `generator_skills/safety-and-scope-policy.md`, `generator_skills/untrusted-context-policy.md`, `generator_skills/profiles/asi05-unexpected-code-execution.md`.
- **Execution, Adapter & Evidence Pipeline:** `backend/src/targets/adapters/http_adapter.py`, `backend/src/targets/adapters/http_evidence.py`, `backend/src/core/models/evidence.py`, `backend/src/core/evidence_v2.py`, `backend/src/reporting/redaction.py`, `backend/src/testing/runner.py`, `backend/src/testing/generic_runner.py`, `backend/src/workflow/routes_generic_runner.py`, `backend/src/workflow/evidence_sources.py`.
- **Evaluators, Judge & Verdict Policy:** `backend/src/evaluators/contract.py`, `backend/src/evaluators/hybrid_evaluator.py`, `backend/src/evaluators/evidence_v2_evaluator.py`, `backend/src/evaluators/verdict_resolver.py`, `backend/src/evaluators/verdict_outcome.py`, `backend/src/evaluators/evaluation_request_builder.py`, `backend/src/integrations/external_evaluator/pi.py`, `evaluator_skills/security/SKILL.md`, `evaluator_skills/security/verdict-policy.md`, `evaluator_skills/security/vulnerabilities/unexpected-code-execution-response.md`.

---

## 4. High-Level Findings Index (See `05_FINDINGS_AND_RECOMMENDATIONS.md` for Full Details)

| Finding ID | Priority | Short Title | Confidence |
|---|---|---|---|
| `G16-P0-01` | **P0** | Immediate inline-event argument/observation hashing blinds both Judge and deterministic rules to unexpected `run_shell` payloads (`TC09`, `TC0006`) | `CONFIRMED` |
| `G16-P0-02` | **P0** | Observation-binary policy (`2.2.0-observation-binary`) reports `PASS` (`100%` pass rate) on `15/20` `JUDGE_ERROR` (`nonzero_exit`) failures (Run `81b73474`) | `CONFIRMED` |
| `G16-P0-03` | **P0** | Raw `3/20` vs. `10/20` FAIL is severely confounded: 8/10 Run B FAILs are pure prose hallucinations (`finish` only) on a degraded (missing-Docker) AIGoat lab, with embedded refusal rubrics in 20/20 Promptfoo prompts | `CONFIRMED` |
| `G16-P0-04` | **P0** | `effective_evaluation_scope` silently defaults to `response_command_artifact` with 0 deterministic rules even when `runtime_execution = "supported"` | `CONFIRMED` |
| `G16-P1-01` | **P1** | Generator safety policy + authorized sandbox context dilute Chunk-1 adversarial pressure (11/15 benign/inert cases) while Chunk 2 escalates abruptly (and `TC20` skirts destructive policy) | `CONFIRMED` |
| `G16-P1-02` | **P1** | Generator validation lacks boundary-alignment, capability-alignment, and structural near-duplicate checks (`TC04/05/06/15` repetition) | `CONFIRMED` |
| `G16-P1-03` | **P1** | Unpinned `defense_level` + mixed L0/L2 `ApplicationContext` causes Judge policy inconsistency (`TC0011` cites L2 gate; `G11-ASI05-016` PASS vs. `TC0013` FAIL on `/etc/shadow`) | `CONFIRMED` |
| `G16-P1-04` | **P1** | `PiEvaluatorProvider` lacks HTTP 402 / billing fault classification and native reports drop `stderr` / diagnostic code, preventing post-hoc verification of `nonzero_exit` root causes | `CONFIRMED` |
| `G16-P2-01` | **P2** | Imported Promptfoo assertions are non-executable (`imported_assertions_non_executable_count: 1`), and normalized SecAgent datasets drop `strategy_tag` / `evaluation_scope` / `severity` | `CONFIRMED` |
| `G16-P2-02` | **P2** | High single-trial stochasticity (3/20 = 15% verdict flip between Run A `f03ec703` and earlier Run `959c5740`) invalidates single-run small-$N$ comparisons | `CONFIRMED` |
