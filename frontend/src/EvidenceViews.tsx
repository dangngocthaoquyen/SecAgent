import { safeLabel } from "./api";
import type { Evidence, Fields, Judge } from "./detailApi";
import { Badge } from "./components";
export function value(v: unknown): string {
  return v === null || v === undefined || v === ""
    ? "Unavailable"
    : safeLabel(String(v));
}
export function Facts({ rows }: { rows: [string, unknown][] }) {
  return (
    <dl className="facts">
      {rows.map(([label, v]) => (
        <div key={label}>
          <dt>{label}</dt>
          <dd>{value(v)}</dd>
        </div>
      ))}
    </dl>
  );
}
export function Text({ text }: { text: string | null | undefined }) {
  return <p className="source-text">{value(text)}</p>;
}
const safeDetails = [
  "declared_tool_call_count",
  "finish_reason",
  "webFetchAttempted",
  "webFetchExecuted",
  "webFetchSource",
  "httpPostAttempted",
  "httpPostExecuted",
  "result_ok",
  "result_status_code",
  "observed_method",
  "receipt_count",
  "receipt_timestamp",
  "page_served",
  "condition",
  "correlation_valid",
  "observation_complete",
];
export function EvidenceCard({ e }: { e: Evidence }) {
  return (
    <article className="evidence-card">
      <h3>{value(e.name ?? e.kind)}</h3>
      <Facts
        rows={[
          ["Kind", e.kind],
          ["Reported source", e.reported_source],
          ["Reported provenance", e.reported_provenance],
          ["Evidence reference", e.source_reference],
          ["Reported success", e.reported_success],
        ]}
      />
      <Facts
        rows={safeDetails
          .filter((k) => k in e.details)
          .map((k) => [k.replaceAll("_", " "), e.details[k]])}
      />
      <p className="caption">
        Historical verification claim: {value(e.verification.reported_status)}.
        Normalizer verification: {value(e.verification.normalizer_status)};
        independent re-verification:{" "}
        {value(e.verification.independent_reverification)}.
      </p>
    </article>
  );
}
export function JudgePanel({
  judge: j,
  title,
}: {
  judge: Judge;
  title: string;
}) {
  return (
    <section className="panel judge-panel">
      <h2>{title}</h2>
      <Facts
        rows={[
          ["Invocation state", j.invocation_state],
          ["Classification", j.classification],
          ["Recommendation", j.recommendation],
          ["JSON validation (reported)", j.reported_json_validation_status],
          [
            "Provider / model",
            [j.provider, j.model].filter(Boolean).join(" / ") || null,
          ],
          ["Provider error", j.provider_fault_code],
          ["Provider exit code", j.provider_exit_code],
          ["Provider duration (ms)", j.provider_duration_ms],
        ]}
      />
      <h3>Recorded explanation</h3>
      <Text text={j.explanation} />
      <Facts
        rows={[
          ["Invocation reason", j.reason],
          ["Downgrade reason", j.downgrade_reason],
        ]}
      />
      <h3>Recorded citations</h3>
      {j.citations.length ? (
        <ul className="citation-list">
          {j.citations.map((c, i) => (
            <li key={i}>
              <b>{value(c.type)}</b>
              <Text text={c.value_preview} />
            </li>
          ))}
        </ul>
      ) : (
        <p>No citations recorded.</p>
      )}
      <p className="caption">
        Judge interpretation is not ground truth. Citations and JSON validation
        are historical records, not revalidated by this UI. No confidence value
        is treated as accuracy.
      </p>
    </section>
  );
}
export function EvidenceSequence({
  evidence,
  execution,
  reportedAt,
}: {
  evidence: Evidence[];
  execution: Fields;
  reportedAt: string | null;
}) {
  const times: [string, unknown][] = [
    ["Execution start (source claim)", execution.started_at],
    ["Execution end (source claim)", execution.ended_at],
    ["Source report timestamp", reportedAt],
  ];
  return (
    <section className="panel">
      <h2>Evidence sequence · recorded entries</h2>
      <p>
        No complete chronology is established. Entries retain source-array order
        for reference, not event order. Times below are recorded claims; none
        are inferred from response text or filenames.
      </p>
      <Facts rows={times} />
      {evidence.length ? (
        <ul className="evidence-sequence">
          {evidence.map((e) => (
            <li key={e.id}>
              <div>
                <strong>
                  {value(e.id)} · {value(e.kind)}
                </strong>
                <Badge value={e.reported_source} />
              </div>
              <p>
                {e.details.receipt_timestamp
                  ? `Recorded receipt timestamp: ${value(e.details.receipt_timestamp)}`
                  : "Event timestamp unavailable"}
              </p>
              <p>Reference: {value(e.source_reference)}</p>
            </li>
          ))}
        </ul>
      ) : (
        <p>
          No evidence entries are available. No execution steps can be
          reconstructed.
        </p>
      )}
    </section>
  );
}
