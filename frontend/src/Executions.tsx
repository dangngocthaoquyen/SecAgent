import { useEffect, useState, type FormEvent } from "react";
import {
  api,
  emptyFilters,
  safeLabel,
  type Filters,
  type Page,
  type Summary,
} from "./api";
import { Badge, Notice } from "./components";
export default function Executions({
  summary,
  onConnection,
}: {
  summary: Summary;
  onConnection: (ok: boolean) => void;
}) {
  const [draft, setDraft] = useState<Filters>({ ...emptyFilters });
  const [filters, setFilters] = useState<Filters>({ ...emptyFilters });
  const [page, setPage] = useState(1),
    [size, setSize] = useState(25),
    [retry, setRetry] = useState(0);
  const [data, setData] = useState<Page | null>(null),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(true);
  useEffect(() => {
    const controller = new AbortController();
    setBusy(true);
    setError("");
    setData(null);
    api
      .executions(filters, page, size, controller.signal)
      .then((result) => {
        if (controller.signal.aborted) return;
        if (
          result.snapshot_sha256 !== summary.snapshot_sha256 ||
          result.page !== page ||
          result.page_size !== size
        )
          throw new Error(
            "The selected reporting snapshot changed. Refresh the dataset from the header before continuing.",
          );
        setData(result);
        onConnection(true);
      })
      .catch((e) => {
        if (!controller.signal.aborted) {
          setError(e.message);
          onConnection(false);
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setBusy(false);
      });
    return () => controller.abort();
  }, [filters, page, size, retry, summary.snapshot_sha256, onConnection]);
  function submit(e: FormEvent) {
    e.preventDefault();
    setFilters({ ...draft, testcase_id: draft.testcase_id.trim() });
    setPage(1);
  }
  function reset() {
    setDraft({ ...emptyFilters });
    setFilters({ ...emptyFilters });
    setPage(1);
  }
  const field = (key: keyof Filters, value: string) =>
    setDraft((d) => ({ ...d, [key]: value }));
  return (
    <>
      <div className="page-title">
        <div>
          <span className="eyebrow">SELECTED DATASET</span>
          <h1>Execution results</h1>
          <p>
            Historical security outcomes, kept separate from execution and
            evidence status.
          </p>
        </div>
      </div>
      <section className="panel results-panel">
        <form className="filters" onSubmit={submit}>
          <label>
            ASI category
            <select
              value={draft.asi_category}
              onChange={(e) => field("asi_category", e.target.value)}
            >
              <option value="">All categories</option>
              {["ASI01", "ASI02", "ASI03", "ASI05"].map((v) => (
                <option key={v}>{v}</option>
              ))}
              <option value="unknown">Unknown</option>
            </select>
          </label>
          <label>
            Target
            <select
              value={draft.target_id}
              onChange={(e) => field("target_id", e.target.value)}
            >
              <option value="">All targets</option>
              {summary.groups.target_id
                .filter((g) => g.key !== null)
                .map((g) => (
                  <option key={g.key} value={g.key!}>
                    {safeLabel(g.key)}
                  </option>
                ))}
            </select>
          </label>
          <label>
            Security verdict
            <select
              value={draft.verdict}
              onChange={(e) => field("verdict", e.target.value)}
            >
              <option value="">All verdicts</option>
              {["PASS", "FAIL", "INCONCLUSIVE"].map((v) => (
                <option key={v}>{v}</option>
              ))}
              <option value="unknown">Unknown</option>
            </select>
          </label>
          <label>
            Exact testcase ID
            <input
              value={draft.testcase_id}
              onChange={(e) => field("testcase_id", e.target.value)}
              placeholder="e.g. GH-WEB-001"
              maxLength={256}
              pattern="[A-Za-z0-9_.:\[\]\-]+"
            />
          </label>
          <button className="primary" type="submit">
            Apply filters
          </button>
          <button type="button" onClick={reset}>
            Reset
          </button>
        </form>
        <p className="filter-note">
          Filters apply to the entire selected dataset on the server. Testcase
          IDs require an exact match.
        </p>
        {error ? (
          <Notice error={error} retry={() => setRetry((n) => n + 1)} />
        ) : busy ? (
          <div className="loading" role="status">
            Loading execution reports…
          </div>
        ) : (
          data && (
            <>
              <div className="result-count" role="status">
                <strong>
                  {data.total} matching{" "}
                  {data.total === 1 ? "report" : "reports"}
                </strong>
                <span>
                  of {summary.counts.recorded_execution_reports} selected
                  execution reports
                </span>
              </div>
              {!data.items.length ? (
                <div className="empty">
                  <span aria-hidden="true">◎</span>
                  <h2>
                    {data.total
                      ? "No records on this page"
                      : "No matching execution reports"}
                  </h2>
                  <p>
                    {data.total
                      ? "Return to the previous page."
                      : "Adjust or reset the filters. No substitute or demo results are displayed."}
                  </p>
                </div>
              ) : (
                <div
                  className="table-scroll"
                  tabIndex={0}
                  role="region"
                  aria-label="Scrollable execution results"
                >
                  <table className="execution-table">
                    <caption className="sr-only">
                      Historical execution reports
                    </caption>
                    <thead>
                      <tr>
                        {[
                          "Testcase",
                          "ASI",
                          "Target",
                          "Security verdict",
                          "Execution status",
                          "Artifact verification",
                          "Response completeness",
                          "Archived assessments",
                        ].map((h) => (
                          <th key={h} scope="col">
                            {h}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {data.items.map((row) => (
                        <tr key={row.report_id}>
                          <th scope="row">
                            <a
                              className="testcase report-link"
                              href={`#execution/${row.report_id}`}
                            >
                              {safeLabel(row.testcase_id)}
                            </a>
                            <small>
                              {row.record_status === "partial"
                                ? "Partial reporting record"
                                : "Recorded execution"}
                            </small>
                          </th>
                          <td>{safeLabel(row.asi_category)}</td>
                          <td className="target-cell">
                            {safeLabel(row.target_id)}
                          </td>
                          <td>
                            <Badge value={row.historical_security_verdict} />
                          </td>
                          <td>
                            <Badge value={row.execution_status} />
                          </td>
                          <td>
                            <Badge value={row.evidence_file_integrity_state} />
                            <small>
                              {row.verification_origin ===
                              "current_api_lifecycle"
                                ? "Current API lifecycle"
                                : "Verification not requested"}
                            </small>
                          </td>
                          <td>
                            <Badge value={row.response_completeness} />
                          </td>
                          <td>{row.linked_assessment_count}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              <div className="pagination">
                <label>
                  Rows per page
                  <select
                    value={size}
                    onChange={(e) => {
                      setSize(Number(e.target.value));
                      setPage(1);
                    }}
                  >
                    {[10, 25, 50, 100].map((n) => (
                      <option key={n}>{n}</option>
                    ))}
                  </select>
                </label>
                <span>
                  Page {page} of {Math.max(1, Math.ceil(data.total / size))} ·{" "}
                  {data.total
                    ? `${(page - 1) * size + (data.items.length ? 1 : 0)}–${(page - 1) * size + data.items.length}`
                    : "0"}{" "}
                  of {data.total}
                </span>
                <div>
                  <button
                    disabled={page <= 1}
                    onClick={() => setPage((n) => n - 1)}
                  >
                    Previous
                  </button>
                  <button
                    disabled={page * size >= data.total}
                    onClick={() => setPage((n) => n + 1)}
                  >
                    Next
                  </button>
                </div>
              </div>
            </>
          )
        )}
      </section>
      <aside className="notice">
        <strong>Reading this table</strong>
        <p>
          “Succeeded” describes execution, not security PASS. “Verified”
          describes local file integrity, not independent attestation of agent
          actions. Unknown response completeness remains unknown. Archived
          assessments are later evaluations of the same evidence, not additional
          executions.
        </p>
      </aside>
    </>
  );
}
