// Synthetic API contract fixtures only. Never imported by the application.
import type { Execution, Summary } from "../api";
export const hash = "a".repeat(64);
export const counts = {
  recorded_execution_reports: 2,
  security_verdicts: { PASS: 0, FAIL: 1, INCONCLUSIVE: 1, unknown: 0 },
  execution_errors: 0,
  successful_execution_reports: 2,
  confirmed_target_invocations: {
    reported_true: 0,
    unknown: 2,
    total_if_fully_known: null,
  },
};
const rate = {
  numerator: 1,
  denominator: 2,
  value: 0.5,
  status: "available",
  definition: "Synthetic test definition",
};
export const summary = {
  summary_schema_version: "1.0.0",
  input_report_schema_version: "2.0.0",
  metric_definition_version: "2C.2.0",
  snapshot_sha256: hash,
  counts,
  archived_assessments: 1,
  groups: {
    asi_category: [{ key: "ASI01", counts }],
    target_id: [{ key: "synthetic-researchbot", counts }],
  },
  metrics: {
    decision_coverage_over_all_records: rate,
    decisive_verdict_rate_among_classified: rate,
    verified_artifact_coverage: rate,
    evidence_coverage: {
      numerator: null,
      denominator: 2,
      value: null,
      status: "unavailable_contract",
      definition: "Unavailable",
    },
  },
  production_comparison_counts: { not_requested: 1, skipped_decisive: 1 },
  archived_comparison_counts: { agreement: 1 },
  limitations: ["Synthetic test data"],
} satisfies Summary & Record<string, unknown>;
export const overview = { api_schema_version: "1.0.0", summary };
export const health = {
  api_schema_version: "1.0.0",
  status: "ok",
  metric_definition_version: "2C.2.0",
  summary_schema_version: "1.0.0",
  report_schema_versions: ["2.0.0"],
  dataset: {
    availability: "available",
    snapshot_sha256: hash,
    execution_records: 2,
    archived_assessments: 1,
  },
};
export const execution: Execution = {
  report_id: `execution:${hash}`,
  execution_id: "synthetic-run",
  testcase_id: "GH-WEB-001",
  target_id: "synthetic-researchbot",
  asi_category: "ASI01",
  historical_security_verdict: "FAIL",
  execution_status: "succeeded",
  record_status: "complete",
  response_completeness: "unknown",
  evidence_file_integrity_state: "verified",
  verification_origin: "current_api_lifecycle",
  linked_assessment_count: 1,
};
export const page = {
  api_schema_version: "1.0.0",
  snapshot_sha256: hash,
  page: 1,
  page_size: 25,
  total: 2,
  items: [
    execution,
    {
      ...execution,
      report_id: `execution:${"b".repeat(64)}`,
      testcase_id: "GH-WEB-C01",
      historical_security_verdict: "INCONCLUSIVE",
      linked_assessment_count: 0,
      evidence_file_integrity_state: "not_performed",
      verification_origin: "not_requested",
    },
  ],
};
