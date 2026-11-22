import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import App from "./App";
import Overview from "./Overview";
import Executions from "./Executions";
import SavedRuns from "./SavedRuns";
import McpRunDetail from "./McpRunDetail";
import { Badge } from "./components";
import { health, overview, page, summary } from "./test/fixtures";
import { detail } from "./test/detailFixtures";
const savedRunsPage = {
  api_schema_version: "1.0.0",
  page: 1,
  page_size: 25,
  total: 1,
  invalid_artifact_count: 0,
  items: [
    {
      run_id: "c".repeat(32),
      kind: "mcp_action",
      testcase_id: "ASI05-DVAA-LAB-READ-001",
      target_id: "dvaa-toolbot",
      asi_category: "ASI05",
      verdict: "ERROR",
      started_at: "2026-11-20T12:00:00+00:00",
      report_sha256: "d".repeat(64),
      evidence_provenance: null,
    },
  ],
};
function mockApi() {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const url = String(input);
    return new Response(
      JSON.stringify(
        url.includes("/health")
          ? health
          : url.includes("/overview")
            ? overview
            : url.includes("/saved-runs")
              ? savedRunsPage
              : page,
      ),
    );
  });
}
describe("Dashboard", () => {
  it("navigates a controlled run reference to its persisted detail", async () => {
    const runId = "b".repeat(32);
    location.hash = `#run/${runId}`;
    const fetcher = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      return new Response(JSON.stringify(url.includes("/health") ? health
        : url.includes("/overview") ? overview
        : url.includes(`/runs/${runId}`) ? { ...detail, run_id: runId }
        : page));
    });
    render(<App />);
    await screen.findByRole("heading", { name: "GH-WEB-001" });
    expect(fetcher.mock.calls.some(([url]) => String(url) === `/api/reports/runs/${runId}`)).toBe(true);
  });
  it("loads counts from reporting API and never counts archived assessment as execution", async () => {
    const fetcher = mockApi();
    render(<App />);
    expect(
      screen.getByText("Loading selected reporting dataset…"),
    ).toBeInTheDocument();
    await screen.findByRole("heading", { name: "Evaluation overview" });
    const counts = screen.getByRole("region", {
      name: "Historical verdict counts",
    });
    for (const [name, value] of [
      ["Execution reports", "2"],
      ["Security PASS", "0"],
      ["Security FAIL", "1"],
      ["INCONCLUSIVE", "1"],
    ]) {
      expect(
        within(
          within(counts).getByRole("heading", { name }).closest("article")!,
        ).getByText(value, { selector: "strong" }),
      ).toBeInTheDocument();
    }
    expect(screen.getByText("Archived Judge assessments")).toBeInTheDocument();
    expect(
      screen.getByText("Unavailable", { selector: "strong" }),
    ).toBeInTheDocument();
    expect(
      fetcher.mock.calls.every(([url]) =>
        String(url).startsWith("/api/reports/"),
      ),
    ).toBe(true);
    fireEvent.click(screen.getByRole("link", { name: "Execution Results" }));
    await screen.findByText("GH-WEB-001");
    expect(screen.getAllByText("succeeded")).toHaveLength(2);
    expect(screen.getAllByText("unknown")).toHaveLength(2);
  });
  it("shows failure and retries without synthetic fallback", async () => {
    const fetcher = vi
      .spyOn(globalThis, "fetch")
      .mockRejectedValue(new Error("private"));
    render(<App />);
    await screen.findByRole("alert");
    expect(screen.queryByText("GH-WEB-001")).not.toBeInTheDocument();
    fetcher.mockImplementation(
      async (input) =>
        new Response(
          JSON.stringify(String(input).includes("health") ? health : overview),
        ),
    );
    fireEvent.click(screen.getByText("Retry reporting API"));
    await screen.findByRole("heading", { name: "Evaluation overview" });
  });
  it("rejects snapshot mismatch", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(
      async (input) =>
        new Response(
          JSON.stringify(
            String(input).includes("health")
              ? {
                  ...health,
                  dataset: {
                    ...health.dataset,
                    snapshot_sha256: "f".repeat(64),
                  },
                }
              : overview,
          ),
        ),
    );
    render(<App />);
    await screen.findByText(/Reporting snapshot is inconsistent/);
  });
  it("shows empty dataset truthfully", () => {
    const s = structuredClone(summary);
    s.counts.recorded_execution_reports = 0;
    render(<Overview summary={s} openResults={() => {}} />);
    expect(
      screen.getByText("No execution reports selected"),
    ).toBeInTheDocument();
  });
  it("applies all filters on the server and resets", async () => {
    const fetcher = mockApi();
    render(<Executions summary={summary} onConnection={() => {}} />);
    await screen.findByText("GH-WEB-001");
    const execForm = screen.getByRole("button", { name: "Apply filters" }).closest("form")!;
    fireEvent.change(within(execForm).getByLabelText("ASI category"), {
      target: { value: "ASI01" },
    });
    fireEvent.change(within(execForm).getByLabelText("Target"), {
      target: { value: "synthetic-researchbot" },
    });
    fireEvent.change(within(execForm).getByLabelText("Security verdict"), {
      target: { value: "FAIL" },
    });
    fireEvent.change(within(execForm).getByLabelText("Exact testcase ID"), {
      target: { value: "GH-WEB-001" },
    });
    fireEvent.click(within(execForm).getByRole("button", { name: "Apply filters" }));
    const execCalls = () =>
      fetcher.mock.calls
        .map(([u]) => String(u))
        .filter((u) => u.includes("/api/reports/executions"));
    await waitFor(() =>
      expect(execCalls().at(-1)).toContain("testcase_id=GH-WEB-001"),
    );
    expect(execCalls().at(-1)).toContain("verdict=FAIL");
    expect(execCalls().at(-1)).toContain("target_id=synthetic-researchbot");
    fireEvent.click(within(execForm).getByRole("button", { name: "Reset" }));
    await waitFor(() =>
      expect(execCalls().at(-1)).toBe("/api/reports/executions?page=1&page_size=25"),
    );
  });
  it("paginates and resets page when changing size", async () => {
    const fetcher = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (input) => {
        const url = String(input);
        if (url.includes("/saved-runs")) {
          return new Response(JSON.stringify(savedRunsPage));
        }
        const q = new URL(url, "http://localhost").searchParams;
        return new Response(
          JSON.stringify({
            ...page,
            page: Number(q.get("page")),
            page_size: Number(q.get("page_size")),
            total: 60,
          }),
        );
      });
    render(<Executions summary={summary} onConnection={() => {}} />);
    await screen.findByText("GH-WEB-001");
    const execSection = screen.getByRole("button", { name: "Apply filters" }).closest("section")!;
    fireEvent.click(within(execSection).getByRole("button", { name: "Next" }));
    await within(execSection).findByText(/Page 2 of 3/);
    fireEvent.change(within(execSection).getByLabelText("Rows per page"), {
      target: { value: "10" },
    });
    const execCalls = () =>
      fetcher.mock.calls
        .map(([u]) => String(u))
        .filter((u) => u.includes("/api/reports/executions"));
    await waitFor(() => expect(execCalls().at(-1)).toContain("page=1&page_size=10"));
  });
  it("shows no matching records", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) =>
      new Response(
        JSON.stringify(
          String(input).includes("/saved-runs")
            ? savedRunsPage
            : { ...page, total: 0, items: [] },
        ),
      ),
    );
    render(<Executions summary={summary} onConnection={() => {}} />);
    await screen.findByText("No matching execution reports");
    const execSection = screen.getByRole("button", { name: "Apply filters" }).closest("section")!;
    expect(within(execSection).getByRole("button", { name: "Next" })).toBeDisabled();
  });
  it("reports table errors without retaining misleading results", async () => {
    let failExecutions = false;
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (url.includes("/saved-runs")) {
        return new Response(JSON.stringify(savedRunsPage));
      }
      if (failExecutions) {
        return new Response("private-path", { status: 503 });
      }
      return new Response(JSON.stringify(page));
    });
    render(<Executions summary={summary} onConnection={() => {}} />);
    await screen.findByText("GH-WEB-001");
    failExecutions = true;
    fireEvent.click(screen.getByText("Apply filters"));
    await screen.findByRole("alert");
    expect(screen.queryByText("GH-WEB-001")).not.toBeInTheDocument();
    expect(screen.queryByText("private-path")).not.toBeInTheDocument();
    failExecutions = false;
    fireEvent.click(screen.getByText("Retry reporting API"));
    await screen.findByText("GH-WEB-001");
  });
  it("renders source labels as text and redacts sensitive locations", () => {
    const s = structuredClone(summary);
    s.groups.target_id[0].key =
      "<img src=x onerror=alert(1)> canary-abcdef https://collector/private";
    const { container } = render(
      <Overview summary={s} openResults={() => {}} />,
    );
    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).not.toContain("canary-abcdef");
    expect(container.textContent).not.toContain("https://collector/private");
  });
  it.each([
    "PASS",
    "FAIL",
    "INCONCLUSIVE",
    "ERROR",
    "succeeded",
    "failed",
    "skipped",
    "unknown",
    "complete",
    "partial",
    "verified",
    "mismatch",
    "missing",
    "unsupported",
    "not_performed",
  ])("renders state %s distinctly", (value) => {
    render(<Badge value={value} />);
    expect(screen.getByText(value.replaceAll("_", " "))).toBeInTheDocument();
  });
  it("renders ERROR MCP saved runs without crashing and filters by date_from/date_to/unknown", async () => {
    const fetcher = mockApi();
    render(<SavedRuns />);
    await screen.findByText("ASI05-DVAA-LAB-READ-001");
    expect(screen.getByText("ERROR")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("ASI"), { target: { value: "unknown" } });
    fireEvent.change(screen.getByLabelText("Date from"), { target: { value: "2026-11-25" } });
    fireEvent.change(screen.getByLabelText("Date to"), { target: { value: "2026-11-20" } });
    fireEvent.click(screen.getByRole("button", { name: "Filter" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/Date from must not be after Date to/);
    fireEvent.change(screen.getByLabelText("Date from"), { target: { value: "2026-11-19" } });
    fireEvent.change(screen.getByLabelText("Date to"), { target: { value: "2026-11-21" } });
    fireEvent.click(screen.getByRole("button", { name: "Filter" }));
    await waitFor(() => expect(String(fetcher.mock.calls.at(-1)![0])).toContain("date_from=2026-11-19"));
    expect(String(fetcher.mock.calls.at(-1)![0])).toContain("date_to=2026-11-21");
    expect(String(fetcher.mock.calls.at(-1)![0])).toContain("asi_category=unknown");
  });
  it("distinguishes ERROR in MCP run detail from a security vulnerability verdict", async () => {
    const runId = "c".repeat(32);
    vi.spyOn(globalThis, "fetch").mockImplementation(async () =>
      new Response(JSON.stringify({
        api_schema_version: "1.0.0",
        run_id: runId,
        report_sha256: "d".repeat(64),
        provenance_limit: "Native MCP report is target telemetry.",
        native_report: {
          testcase_id: "ASI05-DVAA-LAB-READ-001",
          target_id: "dvaa-toolbot",
          evaluation_scope: "execution_action",
          final_verdict: "ERROR",
        },
      })),
    );
    render(<McpRunDetail id={runId} />);
    await screen.findByRole("heading", { name: "MCP action Native Report" });
    expect(screen.getByText("ERROR")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent(/not a security FAIL/i);
  });
});
