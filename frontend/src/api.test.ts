import { describe, expect, it, vi } from "vitest";
import {
  api,
  emptyFilters,
  parseHealth,
  parseOverview,
  parsePage,
  safeLabel,
} from "./api";
import { health, overview, page } from "./test/fixtures";
describe("Reporting contract boundary", () => {
  it("accepts the API schema without transforming security facts", () => {
    expect(parseHealth(health).dataset.execution_records).toBe(2);
    expect(parseOverview(overview).counts.security_verdicts).toEqual({
      PASS: 0,
      FAIL: 1,
      INCONCLUSIVE: 1,
      unknown: 0,
    });
    expect(parsePage(page).items[0].response_completeness).toBe("unknown");
  });
  it.each([
    null,
    {},
    { ...overview, api_schema_version: "9" },
    { ...overview, summary: { ...overview.summary, metrics: {} } },
  ])("rejects malformed overview %#", (value) =>
    expect(() => parseOverview(value)).toThrow(),
  );
  it.each(["complete-ish", true, null])(
    "rejects invented completeness %s",
    (value) =>
      expect(() =>
        parsePage({
          ...page,
          items: [{ ...page.items[0], response_completeness: value }],
        }),
      ).toThrow(),
  );
  it("does not replace unavailable coverage with zero", () =>
    expect(parseOverview(overview).metrics.evidence_coverage.value).toBeNull());
  it("preserves distinct metric denominators", () => {
    const s = structuredClone(overview);
    s.summary.metrics.decision_coverage_over_all_records = {
      ...s.summary.metrics.decision_coverage_over_all_records,
      denominator: 3,
      value: 1 / 3,
    };
    const parsed = parseOverview(s);
    expect(parsed.metrics.decision_coverage_over_all_records.value).toBe(1 / 3);
    expect(parsed.metrics.decisive_verdict_rate_among_classified.value).toBe(
      0.5,
    );
  });
  it("sends only same-origin GET reporting requests with server filters", async () => {
    const fetcher = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response(JSON.stringify(page)));
    await api.executions(
      {
        ...emptyFilters,
        target_id: "lab",
        testcase_id: "GH-WEB-001",
        verdict: "FAIL",
        asi_category: "ASI01",
      },
      1,
      25,
      new AbortController().signal,
    );
    const [url, options] = fetcher.mock.calls[0];
    expect(String(url)).toBe(
      "/api/reports/executions?page=1&page_size=25&asi_category=ASI01&target_id=lab&verdict=FAIL&testcase_id=GH-WEB-001",
    );
    expect(options?.method).toBe("GET");
  });
  it("does not display server error bodies or filesystem paths", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("D:\\private\\canary-secret", { status: 500 }),
    );
    await expect(api.health(new AbortController().signal)).rejects.toThrow(
      "HTTP 500",
    );
  });
  it("reports unreachable service and malformed JSON without fallback data", async () => {
    vi.spyOn(globalThis, "fetch")
      .mockRejectedValueOnce(new Error("secret"))
      .mockResolvedValueOnce(new Response("invalid"));
    await expect(api.health(new AbortController().signal)).rejects.toThrow(
      "unavailable",
    );
    await expect(api.health(new AbortController().signal)).rejects.toThrow(
      "malformed",
    );
  });
  it("redacts sensitive label locations and tokens", () => {
    expect(
      safeLabel(
        "canary-abcdef https://collector/?secret=123 D:\\private\\key Bearer ABC",
      ),
    ).not.toMatch(/abcdef|secret=123|private|Bearer ABC/);
  });
});
