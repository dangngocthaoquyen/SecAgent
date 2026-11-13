import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import ExecutionDetail from "./ExecutionDetail";
import Comparisons from "./Comparisons";
import { parseDetail, parseComparisons, detailApi } from "./detailApi";
import { detail, comparisons } from "./test/detailFixtures";
import { hash, health, overview, page } from "./test/fixtures";
import App from "./App";
const connection = () => {};
describe("Execution detail and evidence semantics", () => {
  it("explains a controlled run missing from the selected reporting root", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 404 }));
    render(<ExecutionDetail id={"b".repeat(32)} run snapshot={hash} onConnection={connection} />);
    expect(await screen.findByRole("alert")).toHaveTextContent(/Saved report unavailable in the selected reporting dataset/);
  });
  it("opens a selected controlled run through the reporting detail view", async () => {
    const runId = "b".repeat(32);
    const fetcher = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ ...detail, run_id: runId,
        execution: { ...detail.execution, source: {
          ...detail.execution.source, reported_provenance: "synthetic_mock" } } })),
    );
    render(<ExecutionDetail id={runId} run snapshot={hash} onConnection={connection} />);
    await screen.findByRole("heading", { name: "GH-WEB-001" });
    expect(fetcher.mock.calls[0][0]).toBe(`/api/reports/runs/${runId}`);
    expect(screen.getAllByText("FAIL").length).toBeGreaterThan(0);
    expect(screen.getByText("synthetic_mock")).toBeInTheDocument();
  });
  it("shows empty comparison sections without manufactured agreements", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({ ...comparisons, production: [], archived: [] }),
      ),
    );
    render(<Comparisons snapshot={hash} onConnection={connection} />);
    await screen.findAllByText("No comparisons available.");
    expect(
      screen.queryByText("agreement", { exact: true }),
    ).not.toBeInTheDocument();
  });
  it("shows an unavailable provider and missing archive verification separately", async () => {
    const d = {
      ...detail,
      execution: {
        ...detail.execution,
        artifact_verification: null,
        judge: {
          ...detail.execution.judge,
          invocation_state: "attempted_failed",
          provider_fault_code: "timeout",
        },
      },
    };
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify(d)),
    );
    render(
      <ExecutionDetail
        id={`execution:${hash}`}
        snapshot={hash}
        onConnection={connection}
      />,
    );
    await screen.findByText("timeout");
    expect(screen.getByText("attempted_failed")).toBeInTheDocument();
    expect(screen.getAllByText("Unavailable").length).toBeGreaterThan(0);
    expect(screen.getAllByText("FAIL").length).toBeGreaterThan(0);
  });
  it("validates the real-shaped detail and comparison contracts", () => {
    expect(parseDetail(detail).execution.security.verdict).toBe("FAIL");
    expect(parseComparisons(comparisons).archived[0].state).toBe("agreement");
  });
  it("separates declarations, recorded GET and archived interpretation", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify(detail)),
    );
    const { container } = render(
      <ExecutionDetail
        id={`execution:${hash}`}
        snapshot={hash}
        onConnection={connection}
      />,
    );
    await screen.findByRole("heading", { name: "GH-WEB-001" });
    expect(screen.getAllByText("http_post").length).toBeGreaterThan(0);
    expect(screen.getAllByText("GET").length).toBeGreaterThan(0);
    expect(screen.getByText("agreement")).toBeInTheDocument();
    expect(screen.getByText("unknown")).toBeInTheDocument();
    expect(container.querySelector("script")).toBeNull();
    expect(
      screen.getByText("<script>do not execute</script>"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/No complete chronology is established/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Recorded receipt timestamp: 2026-01-01/),
    ).toBeInTheDocument();
  });
  it("keeps incomplete control INCONCLUSIVE with missing evidence and unavailable Judge", async () => {
    const d = structuredClone(detail);
    d.execution.security = {
      verdict: "INCONCLUSIVE",
      historical_status: "INCONCLUSIVE",
      reason: "Missing evidence",
    };
    d.execution.observation.evidence = [];
    d.execution.observation.response_preview = "";
    d.execution.linked_archived_assessments = [];
    d.execution.judge = {
      ...d.execution.judge,
      invocation_state: "not_requested",
    };
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify(d)),
    );
    render(
      <ExecutionDetail
        id={`execution:${hash}`}
        snapshot={hash}
        onConnection={connection}
      />,
    );
    await screen.findByText("Missing evidence");
    expect(screen.getAllByText("INCONCLUSIVE")).toHaveLength(2);
    expect(
      screen.getByText(/No evidence entries are available/),
    ).toBeInTheDocument();
    expect(
      screen.getByText("No linked archived assessments available."),
    ).toBeInTheDocument();
    expect(screen.getByText("not_requested")).toBeInTheDocument();
  });
  it("rejects malformed detail and invalid IDs without arbitrary API access", async () => {
    expect(() =>
      parseDetail({
        ...detail,
        execution: { ...detail.execution, report_kind: "archived_assessment" },
      }),
    ).toThrow();
    const f = vi.spyOn(globalThis, "fetch");
    await expect(
      detailApi.execution("../private", new AbortController().signal),
    ).rejects.toThrow("Invalid");
    expect(f).not.toHaveBeenCalled();
  });
  it("rejects snapshot changes and unknown reports safely", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({ ...detail, snapshot_sha256: "c".repeat(64) }),
      ),
    );
    render(
      <ExecutionDetail
        id={`execution:${hash}`}
        snapshot={hash}
        onConnection={connection}
      />,
    );
    await screen.findByRole("alert");
    expect(
      screen.queryByText("Synthetic correlated callback."),
    ).not.toBeInTheDocument();
  });
  it.each([
    "missing_parent_execution",
    "parent_hash_mismatch",
    "unverified_parent_linkage",
  ])("keeps %s archived assessments unlinked", async (linkage) => {
    const c = structuredClone(comparisons);
    c.archived[0].linkage = linkage;
    c.archived[0].state = "unlinked";
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify(c)),
    );
    render(<Comparisons snapshot={hash} onConnection={connection} />);
    await screen.findByText(linkage);
    expect(
      screen.queryByText("Open API-linked parent execution"),
    ).not.toBeInTheDocument();
    expect(screen.getByText("unlinked")).toBeInTheDocument();
  });
  it("preserves disagreement and Judge failure as separate states", async () => {
    const c = structuredClone(comparisons);
    c.archived[0].state = "disagreement";
    c.archived[0].recommendation = "PASS";
    c.production[0].state = "judge_unavailable_or_failed";
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify(c)),
    );
    render(<Comparisons snapshot={hash} onConnection={connection} />);
    await screen.findByText("disagreement");
    expect(screen.getByText("judge_unavailable_or_failed")).toBeInTheDocument();
    expect(screen.getByText("PASS")).toBeInTheDocument();
  });
  it("keeps applied result filters when navigating to detail and back", async () => {
    location.hash = "#executions";
    const fetcher = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(
        async (url) =>
          new Response(
            JSON.stringify(
              String(url).includes("/health")
                ? health
                : String(url).includes("/overview")
                  ? overview
                  : String(url).includes("/executions/execution")
                    ? detail
                    : page,
            ),
          ),
      );
    render(<App />);
    await screen.findByRole("link", { name: "GH-WEB-001" });
    fireEvent.change(screen.getByLabelText("Security verdict"), {
      target: { value: "FAIL" },
    });
    fireEvent.click(screen.getByText("Apply filters"));
    await screen.findByRole("link", { name: "GH-WEB-001" });
    fireEvent.click(screen.getByRole("link", { name: "GH-WEB-001" }));
    await screen.findByRole("heading", { name: "GH-WEB-001" });
    fireEvent.click(screen.getByText("← Back to execution results"));
    await screen.findByRole("heading", { name: "Execution results" });
    expect(screen.getByLabelText("Security verdict")).toHaveValue("FAIL");
    expect(
      fetcher.mock.calls.every(([url]) =>
        String(url).startsWith("/api/reports/"),
      ),
    ).toBe(true);
  });
});
