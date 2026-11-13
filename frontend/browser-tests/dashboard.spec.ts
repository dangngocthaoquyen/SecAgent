import { expect, test } from "@playwright/test";
import { health, overview, page as rows } from "../src/test/fixtures";
import { detail, comparisons } from "../src/test/detailFixtures";
test.beforeEach(async ({ page }) => {
  await page.route("**/api/reports/**", async (route) => {
    const path = new URL(route.request().url());
    const body = path.pathname.includes("/executions/execution")
      ? detail
      : path.pathname.endsWith("/comparisons")
        ? comparisons
        : path.pathname.endsWith("/health")
          ? health
          : path.pathname.endsWith("/overview")
            ? overview
            : {
                ...rows,
                items:
                  path.searchParams.get("verdict") === "FAIL"
                    ? [rows.items[0]]
                    : rows.items,
                total: path.searchParams.get("verdict") === "FAIL" ? 1 : 2,
              };
    await route.fulfill({ json: body });
  });
});
test("mobile detail preserves readable evidence without page overflow", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`/#execution/${detail.execution.report_id}`);
  await expect(
    page.getByRole("heading", { name: "Why this verdict was recorded" }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: "test-results/mobile-detail.png",
    fullPage: false,
  });
});
test("desktop navigation and server-side filtering", async ({ page }) => {
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Evaluation overview" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "View execution results" }).click();
  await expect(
    page.getByRole("rowheader", { name: /GH-WEB-C01/ }),
  ).toBeVisible();
  await page.getByLabel("Security verdict").selectOption("FAIL");
  await page.getByLabel("Exact testcase ID").fill("GH-WEB-001");
  await page.getByRole("button", { name: "Apply filters" }).click();
  await expect(
    page.getByText("1 matching report", { exact: true }),
  ).toBeVisible();
  await expect(page.getByRole("rowheader", { name: /GH-WEB-C01/ })).toHaveCount(
    0,
  );
  await page.getByRole("link", { name: "Skip to content" }).focus();
  await page.keyboard.press("Enter");
  await expect(
    page.getByRole("heading", { name: "Execution results" }),
  ).toBeVisible();
  await expect(page.locator("main")).toBeFocused();
});
test("mobile layout remains within viewport and table scrolls locally", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Evaluation overview" }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await page.getByRole("link", { name: "Execution Results" }).click();
  await expect(page.getByText("2 matching reports")).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: "test-results/mobile-results.png",
    fullPage: true,
  });
});
test("proxy rejects unsafe origin and mutations before forwarding", async ({
  request,
}) => {
  expect(
    (
      await request.get("/api/reports/health", {
        headers: { Origin: "https://untrusted.example" },
      })
    ).status(),
  ).toBe(403);
  expect(
    (
      await request.get("/api/reports/health", {
        headers: { "Sec-Fetch-Site": "cross-site" },
      })
    ).status(),
  ).toBe(403);
  expect((await request.post("/api/reports/health")).status()).toBe(405);
  expect((await request.get("/api/execute")).status()).toBe(405);
});
test("optional real selected dataset through localhost proxy", async ({
  page,
  request,
}) => {
  test.skip(
    process.env.SECAGENT_REPORTING_SMOKE !== "1",
    "Explicit opt-in: requires the existing reporting API, never a target.",
  );
  await page.unroute("**/api/reports/**");
  const calls: string[] = [];
  page.on("request", (req) => calls.push(req.url()));
  const response = await request.get("/api/reports/health", {
    headers: { Origin: "http://127.0.0.1:5173" },
  });
  expect(response.status()).toBe(200);
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Evaluation overview" }),
  ).toBeVisible();
  const metrics = page.getByRole("region", {
    name: "Historical verdict counts",
  });
  for (const [label, value] of [
    ["Execution reports", "2"],
    ["Security PASS", "0"],
    ["Security FAIL", "1"],
    ["INCONCLUSIVE", "1"],
  ]) {
    await expect(
      metrics
        .locator("article")
        .filter({
          has: page.getByRole("heading", { name: label, exact: true }),
        })
        .locator("strong"),
    ).toHaveText(value);
  }
  await expect(page.getByText("Unavailable", { exact: true })).toBeVisible();
  await page.screenshot({
    path: "test-results/real-overview.png",
    fullPage: true,
  });
  await page.getByRole("link", { name: "Execution Results" }).click();
  await expect(page.getByText("2 matching reports")).toBeVisible();
  await expect(
    page.getByRole("rowheader", { name: /GH-WEB-001/ }),
  ).toBeVisible();
  await expect(
    page.getByRole("rowheader", { name: /GH-WEB-C01/ }),
  ).toBeVisible();
  await expect(page.getByText("unknown", { exact: true })).toHaveCount(2);
  await page.getByRole("link", { name: "GH-WEB-001", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Why this verdict was recorded" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "http_post", exact: true }).first(),
  ).toBeVisible();
  await expect(
    page.locator(".detail-page").getByText("GET", { exact: true }).first(),
  ).toBeVisible();
  await expect(
    page.locator(".detail-page").getByText("agreement", { exact: true }),
  ).toBeVisible();
  await expect(
    page.locator(".detail-page").getByText("FAIL", { exact: true }).first(),
  ).toBeVisible();
  await expect(
    page.getByText("No complete chronology is established.", { exact: false }),
  ).toBeVisible();
  await page.screenshot({
    path: "test-results/real-attack-detail.png",
    fullPage: true,
  });
  await page.getByRole("link", { name: "← Back to execution results" }).click();
  await page.getByRole("link", { name: "GH-WEB-C01", exact: true }).click();
  await expect(
    page
      .locator(".detail-page")
      .getByText("INCONCLUSIVE", { exact: true })
      .first(),
  ).toBeVisible();
  await expect(
    page.getByText("No linked archived assessments available."),
  ).toBeVisible();
  await expect(
    page.locator(".detail-page").getByText("PASS", { exact: true }),
  ).toHaveCount(0);
  await page.screenshot({
    path: "test-results/real-control-detail.png",
    fullPage: true,
  });
  await page
    .getByRole("link", { name: "Rule / Pi comparison", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "Archived Judge comparisons" }),
  ).toBeVisible();
  await expect(
    page.locator(".comparison-card").getByText("agreement", { exact: true }),
  ).toBeVisible();
  await page.screenshot({
    path: "test-results/real-comparisons.png",
    fullPage: true,
  });
  await page
    .getByRole("link", { name: "Execution Results", exact: true })
    .click();
  await expect(page.getByText("2 matching reports")).toBeVisible();
  await page.getByLabel("Security verdict").selectOption("FAIL");
  await page.getByRole("button", { name: "Apply filters" }).click();
  await expect(
    page.getByText("1 matching report", { exact: true }),
  ).toBeVisible();
  await page.screenshot({
    path: "test-results/real-results.png",
    fullPage: true,
  });
  expect(calls.every((url) => url.startsWith("http://127.0.0.1:5173/"))).toBe(
    true,
  );
});
