import { useCallback, useEffect, useState } from "react";
import { api, type Summary } from "./api";
import { Notice } from "./components";
import Overview from "./Overview";
import Executions from "./Executions";
import ExecutionDetail from "./ExecutionDetail";
import Comparisons from "./Comparisons";
import TargetConfiguration from './TargetConfiguration';
function route() {
  const hash = location.hash.slice(1);
  return hash === 'targets' || hash === "executions" ||
    hash === "comparisons" ||
    hash.startsWith("execution/") || hash.startsWith("run/")
    ? hash
    : "overview";
}
export default function App() {
  const [view, setView] = useState(route());
  const targetsView = view === 'targets';
  const [summary, setSummary] = useState<Summary | null>(null),
    [error, setError] = useState(""),
    [loading, setLoading] = useState(true),
    [connected, setConnected] = useState(false),
    [revision, setRevision] = useState(0);
  useEffect(() => {
    const listener = () => {
      if (location.hash !== "#main") setView(route());
    };
    window.addEventListener("hashchange", listener);
    return () => window.removeEventListener("hashchange", listener);
  }, []);
  useEffect(() => {
    if (targetsView) return;
    const controller = new AbortController();
    setLoading(true);
    setSummary(null);
    setError("");
    setConnected(false);
    Promise.all([
      api.health(controller.signal),
      api.overview(controller.signal),
    ])
      .then(([health, data]) => {
        if (controller.signal.aborted) return;
        if (
          health.dataset.snapshot_sha256 !== data.snapshot_sha256 ||
          health.dataset.execution_records !==
            data.counts.recorded_execution_reports ||
          health.dataset.archived_assessments !== data.archived_assessments
        )
          throw new Error(
            "Reporting snapshot is inconsistent. Retry after the reporting service has finished restarting.",
          );
        setSummary(data);
        setConnected(true);
      })
      .catch((e) => {
        if (!controller.signal.aborted) setError(e.message);
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [revision, targetsView]);
  const connection = useCallback((ok: boolean) => setConnected(ok), []);
  function navigate(next: string) {
    location.hash = next;
    setView(next);
  }
  return (
    <div className="app">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <aside className="sidebar">
        <a
          href="#overview"
          className="brand"
          onClick={() => navigate("overview")}
        >
          <span className="brand-mark" aria-hidden="true">
            S
          </span>
          <span>
            SecAgent<small>RESEARCH CONSOLE</small>
          </span>
        </a>
        <div className="nav-label">SECURITY TESTING</div>
        <nav aria-label="Security testing navigation"><a href="#targets" aria-current={targetsView?'page':undefined} onClick={()=>navigate('targets')}>Targets</a></nav>
        <div className="nav-label">EVALUATION REPORTS</div>
        <nav aria-label="Main navigation">
          <a
            href="#overview"
            aria-current={view === "overview" ? "page" : undefined}
            onClick={() => navigate("overview")}
          >
            <span aria-hidden="true">◫</span> Evaluation Overview
          </a>
          <a
            href="#executions"
            aria-current={
              view === "executions" || view.startsWith("execution/") || view.startsWith("run/")
                ? "page"
                : undefined
            }
            onClick={() => navigate("executions")}
          >
            <span aria-hidden="true">☷</span> Execution Results
          </a>
          <a
            href="#comparisons"
            aria-current={view === "comparisons" ? "page" : undefined}
            onClick={() => navigate("comparisons")}
          >
            Rule / Pi comparison
          </a>
        </nav>
        <div className="sidebar-foot">
          <span className="dot" /> Local research workspace
          <small>
            Read-only reporting
            <br />
            OWASP Agentic Security · 2026
          </small>
        </div>
      </aside>
      <div className="workspace">
        <header>
          <div className="breadcrumb">
            {targetsView?'Security Testing':'Evaluation'} <span>/</span>{" "}
            <b>
              {targetsView ? 'Targets' : view === "overview"
                ? "Overview"
                : view === "comparisons"
                  ? "Rule / Pi comparison"
                  : view.startsWith("execution/") || view.startsWith("run/")
                    ? "Execution Detail"
                    : "Execution Results"}
            </b>
          </div>
          <div className="header-actions">
            <span
              className={`connection ${connected && !targetsView ? "online" : ""}`}
              role="status"
            >
              <span className="dot" />
              {targetsView ? 'Offline configuration service' : loading
                ? "Connecting to API"
                : connected
                  ? "Reporting API connected"
                  : "Reporting API unavailable"}
            </span>
            <span className="readonly">{targetsView?'No target requests':'Read-only'}</span>
          </div>
        </header>
        <main id="main" tabIndex={-1}>
          {targetsView ? <TargetConfiguration/> : <>
          <div className="dataset-line">
            <span>
              Selected reporting dataset{" "}
              {summary && <code>· {summary.snapshot_sha256.slice(0, 10)}</code>}
            </span>
            <button
              className="text-button"
              onClick={() => setRevision((n) => n + 1)}
              disabled={loading}
            >
              Reload API snapshot
            </button>
          </div>
          <p className="snapshot-help">
            Reports are loaded when the API starts. Reloading retrieves that
            snapshot; restart the reporting service to change the selected
            files.
          </p>
          {loading ? (
            <div className="loading" role="status">
              <div className="skeleton" />
              Loading selected reporting dataset…
            </div>
          ) : error ? (
            <Notice error={error} retry={() => setRevision((n) => n + 1)} />
          ) : (
            summary && (
              <>
                {view === "overview" && (
                  <Overview
                    summary={summary}
                    openResults={() => navigate("executions")}
                  />
                )}
                {(view === "executions" || view.startsWith("execution/")) && (
                  <div hidden={view !== "executions"}>
                    <Executions summary={summary} onConnection={connection} />
                  </div>
                )}
                {(view.startsWith("execution/") || view.startsWith("run/")) && (
                  <ExecutionDetail
                    id={view.slice(view.startsWith("run/") ? "run/".length : "execution/".length)}
                    snapshot={summary.snapshot_sha256}
                    onConnection={connection}
                    run={view.startsWith("run/")}
                  />
                )}
                {view === "comparisons" && (
                  <Comparisons
                    snapshot={summary.snapshot_sha256}
                    onConnection={connection}
                  />
                )}
              </>
            )
          )}
          </>}
          <footer>
            SecAgent · Evaluation & Reporting{" "}
            <span>
              Historical records. Explicit evidence. No target execution.
            </span>
          </footer>
        </main>
      </div>
    </div>
  );
}
