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
import { Badge } from "./components";
import { health, overview, page, summary } from "./test/fixtures";
import { detail } from "./test/detailFixtures";
function mockApi() {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const url = String(input);
    return new Response(
      JSON.stringify(
        url.includes("/health")
          ? health
          : url.includes("/overview")
            ? overview
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
    fireEvent.change(screen.getByLabelText("ASI category"), {
      target: { value: "ASI01" },
    });
    fireEvent.change(screen.getByLabelText("Target"), {
      target: { value: "synthetic-researchbot" },
    });
    fireEvent.change(screen.getByLabelText("Security verdict"), {
      target: { value: "FAIL" },
    });
    fireEvent.change(screen.getByLabelText("Exact testcase ID"), {
      target: { value: "GH-WEB-001" },
    });
    fireEvent.click(screen.getByText("Apply filters"));
    await waitFor(() =>
      expect(String(fetcher.mock.calls.at(-1)![0])).toContain(
        "testcase_id=GH-WEB-001",
      ),
    );
    expect(String(fetcher.mock.calls.at(-1)![0])).toContain("verdict=FAIL");
    expect(String(fetcher.mock.calls.at(-1)![0])).toContain(
      "target_id=synthetic-researchbot",
    );
    fireEvent.click(screen.getByText("Reset"));
    await waitFor(() =>
      expect(String(fetcher.mock.calls.at(-1)![0])).toBe(
        "/api/reports/executions?page=1&page_size=25",
      ),
    );
  });
  it("paginates and resets page when changing size", async () => {
    const fetcher = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (input) => {
        const q = new URL(String(input), "http://localhost").searchParams;
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
    fireEvent.click(screen.getByText("Next"));
    await screen.findByText(/Page 2 of 3/);
    fireEvent.change(screen.getByLabelText("Rows per page"), {
      target: { value: "10" },
    });
    await waitFor(() =>
      expect(String(fetcher.mock.calls.at(-1)![0])).toContain(
        "page=1&page_size=10",
      ),
    );
  });
  it("shows no matching records", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ ...page, total: 0, items: [] })),
    );
    render(<Executions summary={summary} onConnection={() => {}} />);
    await screen.findByText("No matching execution reports");
    expect(screen.getByText("Next")).toBeDisabled();
  });
  it("reports table errors without retaining misleading results", async () => {
    const fetcher = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(JSON.stringify(page)))
      .mockResolvedValue(new Response("private-path", { status: 503 }));
    render(<Executions summary={summary} onConnection={() => {}} />);
    await screen.findByText("GH-WEB-001");
    fireEvent.click(screen.getByText("Apply filters"));
    await screen.findByRole("alert");
    expect(screen.queryByText("GH-WEB-001")).not.toBeInTheDocument();
    expect(screen.queryByText("private-path")).not.toBeInTheDocument();
    fetcher.mockResolvedValue(new Response(JSON.stringify(page)));
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
});
