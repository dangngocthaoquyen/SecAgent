import { safeLabel, type Rate } from "./api";
const descriptions: Record<string, string> = {
  PASS: "Historical security test passed. This is not a new verification of runtime authenticity.",
  FAIL: "Historical test detected the attacker objective or another specified security failure condition.",
  INCONCLUSIVE:
    "Available evidence did not support a definitive security verdict.",
  succeeded:
    "Target execution reported success. This does not mean security PASS.",
  failed: "Technical execution failed; this is not a security FAIL.",
  verified:
    "Local artifact file integrity was verified; this is not remote attestation of runtime behavior.",
  not_performed:
    "Artifact verification was not performed. This does not indicate a mismatch.",
  mismatch: "Artifact integrity verification found a mismatch.",
  unknown: "The selected record does not establish this fact.",
};
export function Badge({ value }: { value: string | null }) {
  const name = value ?? "unknown";
  const tone =
    name === "FAIL" || name === "mismatch"
      ? "danger"
      : name === "PASS"
        ? "success"
        : name === "INCONCLUSIVE" || name === "partial"
          ? "warning"
          : "neutral";
  return (
    <span
      className={`badge ${tone}`}
      title={descriptions[name] ?? name.replaceAll("_", " ")}
    >
      {name.replaceAll("_", " ")}
    </span>
  );
}
export function Metric({
  label,
  value,
  note,
  tone = "",
}: {
  label: string;
  value: string | number;
  note: string;
  tone?: string;
}) {
  return (
    <article className={`metric ${tone}`}>
      <h3>{label}</h3>
      <strong>{value}</strong>
      <p>{note}</p>
    </article>
  );
}
export function RateCard({
  label,
  rate,
  note,
}: {
  label: string;
  rate: Rate;
  note: string;
}) {
  return (
    <article className="rate-card">
      <h3>{label}</h3>
      <strong>
        {rate.value === null
          ? "Unavailable"
          : `${Math.round(rate.value * 1000) / 10}%`}
      </strong>
      <p>
        {rate.value === null
          ? rate.status === "zero_denominator"
            ? "No eligible records"
            : "Evidence sufficiency contract unavailable"
          : `${rate.numerator} / ${rate.denominator} eligible records`}
      </p>
      <div className="meter" aria-hidden="true">
        <span style={{ width: `${(rate.value ?? 0) * 100}%` }} />
      </div>
      <small>{note}</small>
    </article>
  );
}
export function Notice({ error, retry }: { error: string; retry: () => void }) {
  return (
    <div className="notice error" role="alert">
      <strong>Reporting data could not be loaded</strong>
      <p>{error}</p>
      <button onClick={retry}>Retry reporting API</button>
    </div>
  );
}
export function Distribution({
  title,
  rows,
  total,
}: {
  title: string;
  rows: { key: string | null; value: number }[];
  total: number;
}) {
  return (
    <section className="panel distribution">
      <h2>{title}</h2>
      <p className="muted">Selected execution reports</p>
      {rows.length === 0 ? (
        <p>No execution records selected.</p>
      ) : (
        rows.map((row) => (
          <div className="distribution-row" key={row.key ?? "unknown"}>
            <div>
              <span>{safeLabel(row.key)}</span>
              <b>{row.value}</b>
            </div>
            <div className="meter" aria-hidden="true">
              <span
                style={{ width: `${total ? (row.value / total) * 100 : 0}%` }}
              />
            </div>
          </div>
        ))
      )}
    </section>
  );
}
