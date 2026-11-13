import { get } from "./api";
export type Fields = Record<string, string | number | boolean | null>;
export type Judge = {
  invocation_state: string;
  classification: string | null;
  recommendation: string | null;
  explanation: string | null;
  reason: string | null;
  provider: string | null;
  model: string | null;
  reported_json_validation_status: string | null;
  provider_fault_code: string | null;
  downgrade_reason: string | null;
  provider_exit_code: number | null;
  provider_duration_ms: number | null;
  citations: { type: string; value_preview: string }[];
};
export type Evidence = {
  id: string;
  kind: string;
  name: string | null;
  reported_source: string;
  reported_provenance: string | null;
  source_reference: string | null;
  reported_success: boolean | null;
  details: Fields;
  verification: Fields;
};
export type Rule = {
  status: string | null;
  reason: string | null;
  evidence_preview: string | null;
  matched_rule_id: string | null;
};
export type Archive = {
  report_id: string;
  target_execution_performed: false;
  source_reported_at: string | null;
  source_execution: Fields;
  context: Fields;
  judge: Judge;
  comparison: Fields;
  limitations: string[];
};
export type Verification = {
  file_integrity: string;
  internal_evidence_consistency: string;
  collector_canonical_digest: string;
  crosscheck_linkage: string;
  external_action_attestation: string;
  receipt_count: number | null;
  observed_methods: string[];
  checks: Record<string, string>;
  limitations: string[];
};
export type Detail = {
  report_id: string;
  execution_id: string | null;
  identity: Fields;
  source_reported_at: string | null;
  source: Fields;
  execution: Fields;
  security: Fields;
  context: Fields;
  observation: {
    response_preview: string | null;
    preview_redacted: boolean;
    preview_truncated: boolean;
    response_completeness: { state: string };
    evidence: Evidence[];
  };
  deterministic: {
    original: Rule | null;
    baseline: Rule | null;
    effective: Rule | null;
  };
  judge: Judge;
  tool_evidence: Record<
    | "declared_calls"
    | "target_reported_actions"
    | "collector_records"
    | "other_observations",
    Evidence[]
  >;
  artifact_verification: Verification | null;
  verification_origin: string;
  linked_archived_assessments: Archive[];
  limitations: string[];
  technical_errors: Fields[];
};
export type DetailResponse = { snapshot_sha256: string; execution: Detail };
export type Comparison = {
  report_id: string;
  mode: string;
  source_sha256: string;
  parent_source_sha256: string | null;
  linkage: string | null;
  state: string;
  rule_status: string | null;
  classification: string | null;
  recommendation: string | null;
  judge_invocation_state: string;
  provider_diagnostics: Judge;
  verification_origin: string;
};
export type ComparisonsResponse = {
  snapshot_sha256: string;
  production: Comparison[];
  archived: Comparison[];
};

// Check every field rendered by these views. Extra fields are neither displayed nor trusted.
type Obj = Record<string, unknown>;
function obj(v: unknown): Obj {
  if (!v || typeof v !== "object" || Array.isArray(v)) throw Error("contract");
  return v as Obj;
}
function str(v: unknown) {
  if (typeof v !== "string") throw Error("contract");
}
function nullable(v: unknown) {
  if (v !== null) str(v);
}
function array(v: unknown, check: (x: unknown) => void) {
  if (!Array.isArray(v)) throw Error("contract");
  v.forEach(check);
}
function fields(v: unknown) {
  for (const x of Object.values(obj(v)))
    if (x !== null && !["string", "number", "boolean"].includes(typeof x))
      throw Error("contract");
}
function texts(v: unknown) {
  array(v, str);
}
function hash(v: unknown) {
  if (typeof v !== "string" || !/^[a-f0-9]{64}$/.test(v))
    throw Error("contract");
}
function state(v: unknown, allowed: string[]) {
  if (typeof v !== "string" || !allowed.includes(v)) throw Error("contract");
}
function judge(v: unknown) {
  const j = obj(v);
  for (const k of [
    "classification",
    "recommendation",
    "explanation",
    "reason",
    "provider",
    "model",
    "reported_json_validation_status",
    "provider_fault_code",
    "downgrade_reason",
  ])
    nullable(j[k]);
  state(j.invocation_state, [
    "not_requested",
    "skipped_decisive",
    "prevented",
    "attempted_failed",
    "result_available",
    "unknown",
  ]);
  for (const k of ["provider_exit_code", "provider_duration_ms"])
    if (j[k] !== null && typeof j[k] !== "number") throw Error("contract");
  array(j.citations, (c) => {
    str(obj(c).type);
    str(obj(c).value_preview);
  });
}
function evidence(v: unknown) {
  const e = obj(v);
  for (const k of ["id", "kind", "reported_source"]) str(e[k]);
  for (const k of ["name", "reported_provenance", "source_reference"])
    nullable(e[k]);
  if (e.reported_success !== null && typeof e.reported_success !== "boolean")
    throw Error("contract");
  fields(e.details);
  fields(e.verification);
}
function rule(v: unknown) {
  if (v === null) return;
  const r = obj(v);
  for (const k of ["status", "reason", "evidence_preview", "matched_rule_id"])
    nullable(r[k]);
}
function envelope(v: unknown) {
  const o = obj(v);
  if (o.api_schema_version !== "1.0.0") throw Error("contract");
  hash(o.snapshot_sha256);
  return o;
}
export function parseDetail(v: unknown): DetailResponse {
  const o = envelope(v),
    d = obj(o.execution);
  if (
    d.report_kind !== "execution" ||
    d.report_schema_version !== "2.0.0" ||
    !/^execution:[a-f0-9]{64}$/.test(String(d.report_id))
  )
    throw Error("contract");
  nullable(d.execution_id);
  nullable(d.source_reported_at);
  for (const k of ["identity", "source", "execution", "security", "context"])
    fields(d[k]);
  const ob = obj(d.observation);
  nullable(ob.response_preview);
  for (const k of ["preview_redacted", "preview_truncated"])
    if (typeof ob[k] !== "boolean") throw Error("contract");
  state(obj(ob.response_completeness).state, [
    "complete",
    "partial",
    "unknown",
  ]);
  array(ob.evidence, evidence);
  for (const k of ["original", "baseline", "effective"])
    rule(obj(d.deterministic)[k]);
  judge(d.judge);
  for (const k of [
    "declared_calls",
    "target_reported_actions",
    "collector_records",
    "other_observations",
  ])
    array(obj(d.tool_evidence)[k], evidence);
  str(d.verification_origin);
  texts(d.limitations);
  array(d.technical_errors, fields);
  if (d.artifact_verification !== null) {
    const a = obj(d.artifact_verification);
    for (const k of [
      "file_integrity",
      "internal_evidence_consistency",
      "collector_canonical_digest",
      "crosscheck_linkage",
      "external_action_attestation",
    ])
      state(a[k], [
        "verified",
        "mismatch",
        "missing",
        "unsupported",
        "not_performed",
      ]);
    texts(a.observed_methods);
    texts(a.limitations);
    for (const x of Object.values(obj(a.checks))) str(x);
    if (a.receipt_count !== null && typeof a.receipt_count !== "number")
      throw Error("contract");
  }
  array(d.linked_archived_assessments, (v) => {
    const a = obj(v);
    if (
      a.report_kind !== "archived_assessment" ||
      a.target_execution_performed !== false
    )
      throw Error("contract");
    str(a.report_id);
    nullable(a.source_reported_at);
    fields(a.source_execution);
    fields(a.context);
    fields(a.comparison);
    judge(a.judge);
    texts(a.limitations);
  });
  return o as unknown as DetailResponse;
}
export function parseComparisons(v: unknown): ComparisonsResponse {
  const o = envelope(v);
  for (const mode of ["production", "archived"])
    array(o[mode], (v) => {
      const c = obj(v);
      if (c.mode !== mode) throw Error("contract");
      str(c.report_id);
      hash(c.source_sha256);
      if (c.parent_source_sha256 !== null) hash(c.parent_source_sha256);
      for (const k of [
        "linkage",
        "rule_status",
        "classification",
        "recommendation",
      ])
        nullable(c[k]);
      for (const k of [
        "state",
        "judge_invocation_state",
        "verification_origin",
      ])
        str(c[k]);
      judge(c.provider_diagnostics);
    });
  return o as unknown as ComparisonsResponse;
}
export const detailApi = {
  execution(id: string, signal: AbortSignal) {
    if (!/^execution:[a-f0-9]{64}$/.test(id))
      return Promise.reject(new Error("Invalid execution report identity."));
    return get(`executions/${encodeURIComponent(id)}`, parseDetail, signal);
  },
  run(id: string, signal: AbortSignal) {
    if (!/^[a-f0-9]{32}$/.test(id))
      return Promise.reject(new Error("Invalid controlled run identity."));
    return get(`runs/${id}`, (value) => {
      const result = parseDetail(value);
      if ((result as DetailResponse & {run_id?: string}).run_id !== id)
        throw Error("Controlled run identity changed.");
      return result;
    }, signal);
  },
  comparisons: (signal: AbortSignal) =>
    get("comparisons", parseComparisons, signal),
};
