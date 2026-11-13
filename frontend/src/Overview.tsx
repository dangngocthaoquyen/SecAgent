import type { Summary } from "./api";
import { Badge, Distribution, Metric, RateCard } from "./components";
export default function Overview({
  summary: s,
  openResults,
}: {
  summary: Summary;
  openResults: () => void;
}) {
  const c = s.counts,
    verdicts = c.security_verdicts,
    total = c.recorded_execution_reports;
  const pass = total ? (verdicts.PASS / total) * 100 : 0,
    fail = total ? (verdicts.FAIL / total) * 100 : 0,
    inc = total ? (verdicts.INCONCLUSIVE / total) * 100 : 0;
  return (
    <>
      <div className="page-title">
        <div>
          <span className="eyebrow">EVALUATION WORKSPACE</span>
          <h1>Evaluation overview</h1>
          <p>
            A clear view of historical findings and the evidence behind them.
          </p>
        </div>
        <button className="primary" onClick={openResults}>
          View execution results <span aria-hidden="true">↗</span>
        </button>
      </div>
      {!total && (
        <div className="notice">
          <strong>No execution reports selected</strong>
          <p>
            Select reports in the reporting service manifest and restart that
            service. This dashboard does not run tests.
          </p>
        </div>
      )}
      <section className="metrics" aria-label="Historical verdict counts">
        <Metric
          label="Execution reports"
          value={total}
          note="Selected records · excludes archived assessments"
        />
        <Metric
          label="Security PASS"
          value={verdicts.PASS}
          note="Historical security test passed"
          tone="success"
        />
        <Metric
          label="Security FAIL"
          value={verdicts.FAIL}
          note="Historical security failure recorded"
          tone="danger"
        />
        <Metric
          label="INCONCLUSIVE"
          value={verdicts.INCONCLUSIVE}
          note="Insufficient evidence for a definitive verdict"
          tone="warning"
        />
        <Metric
          label="Unknown verdict"
          value={verdicts.unknown}
          note="No historical security verdict available"
        />
      </section>
      <div className="overview-grid">
        <section className="panel">
          <div className="section-title">
            <h2>Security verdict distribution</h2>
            <span className="subtle-label">Historical</span>
          </div>
          <div className="verdict-chart">
            <div
              className="donut"
              role="img"
              aria-label={`Verdicts: ${verdicts.PASS} PASS, ${verdicts.FAIL} FAIL, ${verdicts.INCONCLUSIVE} INCONCLUSIVE, ${verdicts.unknown} unknown`}
              style={{
                background: total
                  ? `conic-gradient(#24866a 0% ${pass}%, #cf5764 ${pass}% ${pass + fail}%, #dbac47 ${pass + fail}% ${pass + fail + inc}%, #a4afbd ${pass + fail + inc}% 100%)`
                  : "#e8ecf1",
              }}
            >
              <div>
                <strong>{total}</strong>
                <span>reports</span>
              </div>
            </div>
            <ul className="legend">
              {["PASS", "FAIL", "INCONCLUSIVE", "unknown"].map((v) => (
                <li key={v}>
                  <Badge value={v} />
                  <b>{verdicts[v]}</b>
                </li>
              ))}
            </ul>
          </div>
          <p className="caption">
            Execution success and security success are different outcomes.
          </p>
        </section>
        <section className="panel">
          <div className="section-title">
            <h2>Rule / Pi assessment</h2>
            <span className="subtle-label">Two separate contexts</span>
          </div>
          <div className="assessment-total">
            <strong>{s.archived_assessments}</strong>
            <div>
              Archived Judge assessments
              <small>Later assessments · no new target execution</small>
            </div>
          </div>
          <table className="comparison-table">
            <caption className="sr-only">Rule and Pi comparison counts</caption>
            <thead>
              <tr>
                <th>Comparison</th>
                <th>Production</th>
                <th>Archived</th>
              </tr>
            </thead>
            <tbody>
              {[
                ["Agreement", "agreement"],
                ["Disagreement", "disagreement"],
              ].map(([label, key]) => (
                <tr key={key}>
                  <th>{label}</th>
                  <td>{s.production_comparison_counts[key] ?? 0}</td>
                  <td>{s.archived_comparison_counts[key] ?? 0}</td>
                </tr>
              ))}
              <tr>
                <th>Other / unavailable</th>
                <td>
                  {Object.entries(s.production_comparison_counts)
                    .filter(([k]) => !["agreement", "disagreement"].includes(k))
                    .reduce((n, [, v]) => n + v, 0)}
                </td>
                <td>
                  {Object.entries(s.archived_comparison_counts)
                    .filter(([k]) => !["agreement", "disagreement"].includes(k))
                    .reduce((n, [, v]) => n + v, 0)}
                </td>
              </tr>
            </tbody>
          </table>
          <p className="caption">
            Agreement is not detection accuracy or ground truth. Missing or
            skipped Judge results are not disagreements.
          </p>
        </section>
      </div>
      <div className="section-heading">
        <h2>Coverage & evidence readiness</h2>
        <span>Unknown values stay unknown</span>
      </div>
      <section className="rates" aria-label="Coverage metrics">
        <RateCard
          label="Decision coverage · all records"
          rate={s.metrics.decision_coverage_over_all_records}
          note="PASS + FAIL / all selected execution records, including unknown and technical-error records."
        />
        <RateCard
          label="Decisiveness · classified verdicts"
          rate={s.metrics.decisive_verdict_rate_among_classified}
          note="PASS + FAIL / PASS + FAIL + INCONCLUSIVE. Unknown verdicts excluded."
        />
        <RateCard
          label="Verified artifact coverage"
          rate={s.metrics.verified_artifact_coverage}
          note="File integrity coverage; it does not establish full runtime authenticity."
        />
        <RateCard
          label="Evidence sufficiency coverage"
          rate={s.metrics.evidence_coverage}
          note="A decisive historical verdict does not establish sufficient or independently attested evidence."
        />
      </section>
      <div className="overview-grid">
        <Distribution
          title="By ASI category"
          rows={s.groups.asi_category.map((g) => ({
            key: g.key,
            value: g.counts.recorded_execution_reports,
          }))}
          total={total}
        />
        <Distribution
          title="By target"
          rows={s.groups.target_id.map((g) => ({
            key: g.key,
            value: g.counts.recorded_execution_reports,
          }))}
          total={total}
        />
      </div>
      <div className="scope-line">
        <span>
          <b>{c.successful_execution_reports}</b> successful execution reports
        </span>
        <span>
          <b>{c.execution_errors}</b> execution errors
        </span>
        <span>
          <b>
            {c.confirmed_target_invocations.total_if_fully_known ?? "Unknown"}
          </b>{" "}
          confirmed invocation total ({c.confirmed_target_invocations.unknown}{" "}
          records with unknown scope)
        </span>
      </div>
      <aside className="notice research">
        <strong>Research interpretation</strong>
        <p>
          Historical verdicts are preserved, not re-evaluated here. Artifact
          checks verify local files, not remote event authenticity. The
          GH-WEB-001 isolated DVAA experiment used deterministic runtime
          behavior; it does not establish autonomous DeepSeek tool selection.
          The preceding GH-WEB-C01 control was INCONCLUSIVE.
        </p>
      </aside>
    </>
  );
}
