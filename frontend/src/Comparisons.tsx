import { useEffect, useState } from "react";
import { detailApi, type ComparisonsResponse } from "./detailApi";
import { Notice } from "./components";
import { Facts, JudgePanel, value } from "./EvidenceViews";
export default function Comparisons({
  snapshot,
  onConnection,
}: {
  snapshot: string;
  onConnection: (ok: boolean) => void;
}) {
  const [data, setData] = useState<ComparisonsResponse | null>(null),
    [error, setError] = useState(""),
    [retry, setRetry] = useState(0);
  useEffect(() => {
    const c = new AbortController();
    setData(null);
    setError("");
    detailApi
      .comparisons(c.signal)
      .then((r) => {
        if (c.signal.aborted) return;
        if (r.snapshot_sha256 !== snapshot)
          throw Error("Reporting snapshot changed. Reload API snapshot.");
        setData(r);
        onConnection(true);
      })
      .catch((e) => {
        if (!c.signal.aborted) {
          setError(e.message);
          onConnection(false);
        }
      });
    return () => c.abort();
  }, [snapshot, retry, onConnection]);
  if (error)
    return <Notice error={error} retry={() => setRetry((n) => n + 1)} />;
  if (!data)
    return (
      <div className="loading" role="status">
        Loading Rule / Pi comparisons…
      </div>
    );
  return (
    <div className="detail-page">
      <div className="page-title">
        <div>
          <span className="eyebrow">EVALUATION CONTEXTS</span>
          <h1>Rule / Pi comparison</h1>
          <p>
            Recorded comparisons, not accuracy measurements or new security
            decisions.
          </p>
        </div>
      </div>
      {(["production", "archived"] as const).map((mode) => (
        <section className="panel" key={mode}>
          <h2>
            {mode === "production"
              ? "Production Judge comparisons"
              : "Archived Judge comparisons"}
          </h2>
          <p>
            {mode === "production"
              ? "Original execution pipeline, including skipped and unavailable Judge results."
              : "Later assessments only. Unmatched or mismatched parents remain separate; no new execution is counted."}
          </p>
          {!data[mode].length && <p>No comparisons available.</p>}
          {data[mode].map((c, i) => (
            <article className="comparison-card" key={`${c.report_id}-${i}`}>
              <h3>{value(c.report_id)}</h3>
              <Facts
                rows={[
                  ["Rule status", c.rule_status],
                  ["Judge classification", c.classification],
                  ["Judge recommendation", c.recommendation],
                  ["Comparison", c.state],
                  ["Parent linkage", c.linkage],
                  ["Judge invocation", c.judge_invocation_state],
                  ["Verification origin", c.verification_origin],
                ]}
              />
              {mode === "production" ? (
                <a className="back-link" href={`#execution/${c.report_id}`}>
                  Open original execution
                </a>
              ) : c.linkage === "matched_selected_source" &&
                c.parent_source_sha256 ? (
                <a
                  className="back-link"
                  href={`#execution/execution:${c.parent_source_sha256}`}
                >
                  Open API-linked parent execution
                </a>
              ) : (
                <p>
                  Parent execution is not verified as linked in this selection.
                  No detail link is inferred.
                </p>
              )}
              <details>
                <summary>Judge explanation, citations and diagnostics</summary>
                <JudgePanel
                  judge={c.provider_diagnostics}
                  title={
                    mode === "production"
                      ? "Production assessment"
                      : "Archived assessment"
                  }
                />
              </details>
            </article>
          ))}
        </section>
      ))}
      <aside className="notice">
        Agreement is not ground truth. A disagreement never replaces a
        historical verdict or overrides stored collector evidence. Target
        execution and observation completeness are not established by Judge
        agreement.
      </aside>
    </div>
  );
}
