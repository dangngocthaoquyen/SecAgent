import { useEffect, useState } from "react";
import { detailApi, type Detail } from "./detailApi";
import { ApiError } from "./api";
import { Badge, Notice } from "./components";
import DownloadReport from './DownloadReport';
import {
  EvidenceCard,
  EvidenceSequence,
  Facts,
  JudgePanel,
  Text,
  value,
} from "./EvidenceViews";
export default function ExecutionDetail({
  id,
  snapshot,
  onConnection,
  run = false,
}: {
  id: string;
  snapshot: string;
  onConnection: (ok: boolean) => void;
  run?: boolean;
}) {
  const [data, setData] = useState<Detail | null>(null),
    [requestCount, setRequestCount] = useState<number | null>(null),
    [error, setError] = useState(""),
    [retry, setRetry] = useState(0);
  useEffect(() => {
    const c = new AbortController();
    setData(null);
    setRequestCount(null);
    setError("");
    (run ? detailApi.run(id, c.signal) : detailApi.execution(id, c.signal))
      .then((r) => {
        if (c.signal.aborted) return;
        if (r.snapshot_sha256 !== snapshot || (!run && r.execution.report_id !== id))
          throw Error(
            "Reporting snapshot or execution identity changed. Reload API snapshot.",
          );
        setData(r.execution);
        setRequestCount(r.target_request_count ?? null);
        onConnection(true);
      })
      .catch((e) => {
        if (!c.signal.aborted) {
          setError(run && e instanceof ApiError && e.status === 404
            ? "Saved report unavailable in the selected reporting dataset. Ask the operator to select the controlled-run root or verify the artifact."
            : run && e instanceof ApiError && e.status === 409
              ? "Saved run failed integrity or schema validation. Ask the operator to inspect the report artifact."
              : e.message);
          onConnection(e instanceof ApiError);
        }
      });
    return () => c.abort();
  }, [id, snapshot, retry, onConnection, run]);
  if (error)
    return <Notice error={error} retry={() => setRetry((x) => x + 1)} />;
  if (!data)
    return (
      <div role="status" className="loading">
        Loading execution detail…
      </div>
    );
  const d = data,
    a = d.artifact_verification;
  const responseMetadata = d.observation.evidence.find(item=>item.kind==='http_response_metadata'
    && item.reported_source==='http_response');
  return (
    <div className="detail-page">
      <a className="back-link" href="#executions">
        ← Back to execution results
      </a>
      <DownloadReport kind={run?'runs':'executions'} id={id}/>
      <div className="page-title">
        <div>
          <span className="eyebrow">{run ? "CONTROLLED RUN" : "HISTORICAL EXECUTION"}</span>
          <h1>{value(d.identity.testcase_id)}</h1>
          <p>
            {value(d.identity.target_id)} · {value(d.identity.asi_category)}
          </p>
        </div>
        <Badge
          value={
            typeof d.security.verdict === "string" ? d.security.verdict : null
          }
        />
      </div>
      <section className="panel">
        <h2>Why this verdict was recorded</h2>
        <Text text={d.security.reason as string | null} />
        <Facts
          rows={[
            [run ? "Recorded status" : "Historical status", d.security.historical_status],
            ["Technical execution status", d.execution.status],
            ...(run ? [["Recorded target requests", requestCount] as [string, unknown]] : []),
            [
              "Response completeness",
              d.observation.response_completeness.state,
            ],
            ["Execution identity", d.execution_id],
            ["Report identity", d.report_id],
          ]}
        />
        <p className="caption">
          Recorded decision preserved. Execution success is not security PASS;
          unknown completeness is not complete.
        </p>
      </section>
      {d.imported_provenance&&<section className="panel">
        <h2>Imported testcase provenance</h2>
        <Facts rows={Object.entries(d.imported_provenance).map(([key,item])=>[key.replaceAll('_',' '),item])}/>
        <p>Source taxonomy and assertions are untrusted metadata. A pinned native binding, when shown above, supplies reviewed response rules. Direct chat alone does not establish a fetched-page injection or independently verified tool effect.</p>
      </section>}
      <section className="panel">
        <h2>Task context · original execution record</h2>
        <Facts
          rows={[
            ["Legitimate goal", d.context.legitimate_goal],
            ["Attacker goal", d.context.attacker_goal],
            ["Attack entry point", d.context.attack_entry_point],
            ["Trust boundary", d.context.trust_boundary],
          ]}
        />
        <p className="caption">
          Unavailable goals are not reconstructed from the testcase name,
          response or later assessment.
        </p>
      </section>
      <section className="panel">
        <h2>Target response preview</h2>
        <p>
          Untrusted target-produced text ·{" "}
          {d.observation.preview_redacted
            ? "redacted"
            : "sanitized API preview"}{" "}
          ·{" "}
          {d.observation.preview_truncated
            ? "truncated"
            : "no truncation reported"}
        </p>
        <Text text={d.observation.response_preview} />
        {d.imported_provenance&&responseMetadata&&<Facts rows={[
          ['Target-reported finish reason',responseMetadata.details.finish_reason],
          ['Assistant text field present',responseMetadata.details.assistant_content_present],
          ['Target-declared tool calls',responseMetadata.details.declared_tool_call_count],
        ]}/>}
        {d.imported_provenance&&!d.observation.response_preview&&<p role="status">No assistant response text was captured. HTTP success can still accompany a null assistant message, a tool-call finish, or an incomplete response; see the target-reported response metadata below. No response content is inferred.</p>}
      </section>
      <section className="panel">
        <h2>Deterministic evaluation</h2>
        {(["original", "baseline", "effective"] as const).map((k) => (
          <details key={k} open={k === "original"}>
            <summary>{k} recorded rule result</summary>
            {d.deterministic[k] ? (
              <Facts
                rows={[
                  ["Status", d.deterministic[k]!.status],
                  ["Matched rule", d.deterministic[k]!.matched_rule_id],
                  ["Reason", d.deterministic[k]!.reason],
                  ["Evidence preview", d.deterministic[k]!.evidence_preview],
                ]}
              />
            ) : (
              <p>Unavailable</p>
            )}
          </details>
        ))}
      </section>
      <section className="panel">
        <h2>Tool declarations and recorded actions</h2>
        <p>
          A tool declaration is not successful execution. Target-reported action
          metadata remains a claim. A declared http_post must not be read as an
          observed HTTP POST.
        </p>
        {(
          [
            ["declared_calls", "Declared tool calls"],
            [
              "target_reported_actions",
              "Target-reported metadata and action claims",
            ],
            ["collector_records", "Stored collector observations"],
            ["other_observations", "Other recorded observations"],
          ] as const
        ).map(([key, title]) => (
          <div key={key} className="evidence-group">
            <h3>{title}</h3>
            {d.tool_evidence[key].length ? (
              d.tool_evidence[key].map((e) => <EvidenceCard key={e.id} e={e} />)
            ) : (
              <p>No entries available.</p>
            )}
          </div>
        ))}
      </section>
      <EvidenceSequence
        evidence={d.observation.evidence}
        execution={d.execution}
        reportedAt={d.source_reported_at}
      />
      <section className="panel">
        <h2>Artifact verification and provenance</h2>
        <Facts
          rows={[
            ["Verification origin", d.verification_origin],
            ["Source-reported provenance", d.source.reported_provenance],
            ["File-byte SHA256 integrity", a?.file_integrity],
            ["Stored evidence consistency", a?.internal_evidence_consistency],
            ["Collector canonical JSON digest", a?.collector_canonical_digest],
            ["Cross-check linkage", a?.crosscheck_linkage],
            ["External action attestation", a?.external_action_attestation],
            ["Stored receipt count", a?.receipt_count],
            [
              "Methods in stored collector records",
              a?.observed_methods.join(", ") || null,
            ],
          ]}
        />
        <p>
          Local hash checks verify stored artifacts, not remote authenticity.
          Reading a stored receipt does not newly observe the historical
          request.
        </p>
        {a && (
          <details>
            <summary>Individual stored-record checks</summary>
            <Facts rows={Object.entries(a.checks)} />
          </details>
        )}
      </section>
      <JudgePanel
        judge={d.judge}
        title="Production Judge · original execution"
      />
      <section className="panel">
        <h2>Linked archived assessments</h2>
        <p>
          Later research assessments of the same evidence, not additional target
          executions. They do not overwrite the historical verdict.
        </p>
        {!d.linked_archived_assessments.length && (
          <p>No linked archived assessments available.</p>
        )}
        {d.linked_archived_assessments.map((item) => (
          <article className="archived-card" key={item.report_id}>
            <h3>{value(item.report_id)}</h3>
            <Facts
              rows={[
                ["Comparison recorded", item.comparison.reported_status],
                ["Comparison state", item.comparison.state],
                [
                  "Original verdict snapshot",
                  item.source_execution.original_verdict_snapshot,
                ],
                [
                  "Original rule snapshot",
                  item.source_execution.deterministic_verdict,
                ],
                ["Target execution performed", item.target_execution_performed],
                ["Assessment timestamp (reported)", item.source_reported_at],
                [
                  "Legitimate goal (assessment source)",
                  item.context.legitimate_goal,
                ],
                [
                  "Attacker goal (assessment source)",
                  item.context.attacker_goal,
                ],
              ]}
            />
            <JudgePanel judge={item.judge} title="Archived Pi Judge" />
            <ul>
              {item.limitations.map((s, i) => (
                <li key={i}>{value(s)}</li>
              ))}
            </ul>
          </article>
        ))}
        <a className="back-link" href="#comparisons">
          View all Rule / Pi comparisons →
        </a>
      </section>
      <section className="panel">
        <h2>Limitations and technical errors</h2>
        <ul>
          {[...d.limitations, ...(a?.limitations ?? [])].map((s, i) => (
            <li key={i}>{value(s)}</li>
          ))}
        </ul>
        {d.technical_errors.length ? (
          d.technical_errors.map((e, i) => (
            <Facts
              key={i}
              rows={[
                ["Stage", e.stage],
                ["Code", e.code],
                ["Safe message", e.safe_message],
              ]}
            />
          ))
        ) : (
          <p>No technical errors recorded.</p>
        )}
        <p>
          Missing evidence is not proof of defense. The deterministic DVAA
          ResearchBot experiment does not establish autonomous LLM tool
          selection.
        </p>
      </section>
    </div>
  );
}
