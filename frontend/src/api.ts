export type Verdict = "PASS" | "FAIL" | "INCONCLUSIVE" | null;
export type Rate = {
  numerator: number | null;
  denominator: number;
  value: number | null;
  status: string;
  definition: string;
};
export type Counts = {
  recorded_execution_reports: number;
  security_verdicts: Record<string, number>;
  execution_errors: number;
  successful_execution_reports: number;
  confirmed_target_invocations: {
    reported_true: number;
    unknown: number;
    total_if_fully_known: number | null;
  };
};
export type Group = { key: string | null; counts: Counts };
export type Summary = {
  snapshot_sha256: string;
  counts: Counts;
  archived_assessments: number;
  groups: { asi_category: Group[]; target_id: Group[] };
  metrics: Record<
    | "decision_coverage_over_all_records"
    | "decisive_verdict_rate_among_classified"
    | "verified_artifact_coverage"
    | "evidence_coverage",
    Rate
  >;
  production_comparison_counts: Record<string, number>;
  archived_comparison_counts: Record<string, number>;
  limitations: string[];
};
export type Health = {
  dataset: {
    availability: string;
    snapshot_sha256: string;
    execution_records: number;
    archived_assessments: number;
  };
};
export type Execution = {
  report_id: string;
  execution_id: string | null;
  testcase_id: string | null;
  target_id: string | null;
  asi_category: string | null;
  historical_security_verdict: Verdict;
  execution_status: string;
  record_status: string;
  response_completeness: string;
  evidence_file_integrity_state: string;
  verification_origin: string;
  linked_assessment_count: number;
};
export type Page = {
  snapshot_sha256: string;
  page: number;
  page_size: number;
  total: number;
  items: Execution[];
};
export type Filters = {
  asi_category: string;
  target_id: string;
  verdict: string;
  testcase_id: string;
};
export const emptyFilters: Filters = {
  asi_category: "",
  target_id: "",
  verdict: "",
  testcase_id: "",
};

// Validate the consumed contract instead of casting arbitrary JSON into UI facts.
type Obj = Record<string, unknown>;
function object(v: unknown): Obj {
  if (!v || typeof v !== "object" || Array.isArray(v))
    throw new Error("contract");
  return v as Obj;
}
function count(v: unknown): number {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0)
    throw new Error("contract");
  return v;
}
function text(v: unknown): string {
  if (typeof v !== "string" || v.length > 20000) throw new Error("contract");
  return v;
}
function nullableText(v: unknown): string | null {
  return v === null ? null : text(v);
}
function oneOf(v: unknown, values: readonly unknown[]) {
  if (!values.includes(v)) throw new Error("contract");
}
function sha(v: unknown) {
  if (!/^[a-f0-9]{64}$/.test(text(v))) throw new Error("contract");
}
function counts(v: unknown) {
  const c = object(v);
  count(c.recorded_execution_reports);
  count(c.execution_errors);
  count(c.successful_execution_reports);
  const verdicts = object(c.security_verdicts);
  for (const k of ["PASS", "FAIL", "INCONCLUSIVE", "unknown"])
    count(verdicts[k]);
  const scope = object(c.confirmed_target_invocations);
  count(scope.reported_true);
  count(scope.unknown);
  if (scope.total_if_fully_known !== null) count(scope.total_if_fully_known);
}
function countMap(v: unknown) {
  for (const n of Object.values(object(v))) count(n);
}
function base(v: unknown) {
  const o = object(v);
  oneOf(o.api_schema_version, ["1.0.0"]);
  return o;
}
export function parseHealth(v: unknown): Health {
  const o = base(v);
  oneOf(o.status, ["ok"]);
  oneOf(o.metric_definition_version, ["2C.2.0"]);
  oneOf(o.summary_schema_version, ["1.0.0"]);
  if (
    !Array.isArray(o.report_schema_versions) ||
    !o.report_schema_versions.includes("2.0.0")
  )
    throw new Error("contract");
  const d = object(o.dataset);
  oneOf(d.availability, ["available", "empty"]);
  sha(d.snapshot_sha256);
  count(d.execution_records);
  count(d.archived_assessments);
  return o as unknown as Health;
}
export function parseOverview(v: unknown): Summary {
  const s = object(base(v).summary);
  oneOf(s.summary_schema_version, ["1.0.0"]);
  oneOf(s.input_report_schema_version, ["2.0.0"]);
  oneOf(s.metric_definition_version, ["2C.2.0"]);
  sha(s.snapshot_sha256);
  counts(s.counts);
  count(s.archived_assessments);
  for (const key of ["asi_category", "target_id"]) {
    const g = object(s.groups)[key];
    if (!Array.isArray(g)) throw new Error("contract");
    for (const item of g) {
      const row = object(item);
      nullableText(row.key);
      counts(row.counts);
    }
  }
  for (const key of [
    "decision_coverage_over_all_records",
    "decisive_verdict_rate_among_classified",
    "verified_artifact_coverage",
    "evidence_coverage",
  ]) {
    const r = object(object(s.metrics)[key]);
    count(r.denominator);
    if (r.numerator !== null) count(r.numerator);
    text(r.definition);
    oneOf(r.status, ["available", "zero_denominator", "unavailable_contract"]);
    if (
      r.value !== null &&
      (typeof r.value !== "number" ||
        !Number.isFinite(r.value) ||
        r.value < 0 ||
        r.value > 1)
    )
      throw new Error("contract");
    if ((r.status === "available") !== (r.value !== null))
      throw new Error("contract");
  }
  countMap(s.production_comparison_counts);
  countMap(s.archived_comparison_counts);
  if (!Array.isArray(s.limitations)) throw new Error("contract");
  s.limitations.forEach(text);
  return s as unknown as Summary;
}
export function parsePage(v: unknown): Page {
  const p = base(v);
  sha(p.snapshot_sha256);
  count(p.page);
  count(p.page_size);
  count(p.total);
  if (
    Number(p.page) < 1 ||
    Number(p.page_size) < 1 ||
    Number(p.page_size) > 100 ||
    !Array.isArray(p.items) ||
    p.items.length > Number(p.page_size)
  )
    throw new Error("contract");
  for (const value of p.items) {
    const r = object(value);
    if (!/^execution:[a-f0-9]{64}$/.test(text(r.report_id)))
      throw new Error("contract");
    for (const k of ["execution_id", "testcase_id", "target_id"])
      nullableText(r[k]);
    oneOf(r.asi_category, ["ASI01", "ASI02", "ASI03", "ASI05", null]);
    oneOf(r.historical_security_verdict, [
      "PASS",
      "FAIL",
      "INCONCLUSIVE",
      null,
    ]);
    oneOf(r.execution_status, [
      "succeeded",
      "failed",
      "skipped",
      "not_started",
      "unknown",
    ]);
    oneOf(r.record_status, ["complete", "partial"]);
    oneOf(r.response_completeness, ["complete", "partial", "unknown"]);
    oneOf(r.evidence_file_integrity_state, [
      "verified",
      "mismatch",
      "missing",
      "unsupported",
      "not_performed",
    ]);
    oneOf(r.verification_origin, ["current_api_lifecycle", "not_requested"]);
    count(r.linked_assessment_count);
  }
  return p as unknown as Page;
}
export class ApiError extends Error {
  constructor(message: string, public readonly status?: number) {
    super(message);
  }
}
export async function get<T>(
  route: string,
  parse: (v: unknown) => T,
  signal: AbortSignal,
): Promise<T> {
  try {
    const response = await fetch(`/api/reports/${route}`, {
      method: "GET",
      credentials: "omit",
      cache: "no-store",
      signal: AbortSignal.any([signal, AbortSignal.timeout(12000)]),
    });
    if (!response.ok)
      throw new ApiError(
        `Reporting API returned HTTP ${response.status}. Check the local reporting service and dataset.`,
        response.status,
      );
    try {
      return parse(await response.json());
    } catch {
      throw new ApiError(
        "The reporting API returned an unsupported or malformed response. No results are shown.",
      );
    }
  } catch (error) {
    if (signal.aborted) throw error;
    if (error instanceof ApiError) throw error;
    throw new ApiError(
      "The reporting API is unavailable or timed out. Start the local reporting service on port 8091, then retry.",
    );
  }
}
export const api = {
  health: (signal: AbortSignal) => get("health", parseHealth, signal),
  overview: (signal: AbortSignal) => get("overview", parseOverview, signal),
  executions: (
    filters: Filters,
    page: number,
    size: number,
    signal: AbortSignal,
  ) => {
    const query = new URLSearchParams({
      page: String(page),
      page_size: String(size),
    });
    for (const [k, v] of Object.entries(filters)) if (v) query.set(k, v);
    return get(`executions?${query}`, parsePage, signal);
  },
};

// Defense in depth for displayed labels. Source bodies and paths are never displayed.
export function safeLabel(value: string | null): string {
  if (!value) return "Unknown";
  return value
    .replace(
      /(?:https?:\/\/|[a-z]:[\\/]|\\\\|\/(?:home|Users|tmp|mnt|etc|var)\/)[^\s]+/gi,
      "[redacted location]",
    )
    .replace(/canary[-_.:=][a-z0-9_-]+/gi, "[redacted canary]")
    .replace(/(?:sk-|Bearer\s+)[a-z0-9_-]+/gi, "[redacted credential]");
}
