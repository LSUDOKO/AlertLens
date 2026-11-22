import { expect, test } from "@playwright/test";

const API = process.env.API_URL || "http://127.0.0.1:8000";

test.beforeEach(async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  (page as unknown as { errors: string[] }).errors = errors;
});

test.afterEach(async ({ page }) => {
  expect((page as unknown as { errors: string[] }).errors).toEqual([]);
});

test("hero shows live benchmark numbers", async ({ page, request }) => {
  const bench = await (await request.get(`${API}/v2/benchmark`)).json();
  await page.goto("/");
  await expect(page.locator(".wordmark")).toContainText("alertlens");
  await expect(page.locator(".dim-h")).toContainText(bench.simulated.meta.alerts.toLocaleString("en-GB"));
});

test("analyzer flags the planted instruction and labels every claim's source", async ({ page }) => {
  await page.goto("/#analyze");
  await expect(page.locator(".quarantine")).toContainText("Hidden instructions found", { timeout: 30_000 });
  await expect(page.locator(".sev-head .sev")).toHaveText("critical");
  const chips = page.locator(".claim .contrib span");
  expect(await chips.count()).toBeGreaterThan(3);
  await expect(chips.first()).not.toContainText("?");
  await page.getByRole("button", { name: "Manager" }).click();
  await expect(page.locator(".passage").first()).toBeVisible();
});

test("red team: naive is fooled, AlertLens is not, and the adaptive attacker changes nothing", async ({ page }) => {
  await page.goto("/#redteam");
  await page.getByRole("button", { name: "Attack", exact: true }).click();
  await expect(page.locator(".duel-card").first()).toContainText("Fooled", { timeout: 30_000 });
  await expect(page.locator(".duel-card").nth(1)).toContainText("Not fooled");
  await page.getByRole("button", { name: "Run the attacker" }).click();
  await expect(page.locator(".adaptive .res-card")).toContainText("Attempts that changed a decision", { timeout: 60_000 });
  await expect(page.locator(".adaptive .nb.null b")).toHaveText(/^0 of \d+$/);
});

test("incident graph draws the pivot account", async ({ page }) => {
  await page.goto("/#incident");
  await page.getByRole("button", { name: "Build the incident" }).click();
  await expect(page.locator("svg.graph .node.pivot")).toHaveCount(1, { timeout: 30_000 });
  expect(await page.locator("svg.graph .node").count()).toBeGreaterThan(3);
  await expect(page.locator(".timeline li")).toHaveCount(4);
});

test("results match the committed benchmark files", async ({ page, request }) => {
  const bench = await (await request.get(`${API}/v2/benchmark`)).json();
  await page.goto("/#results");
  const card = page.locator(".res-card").first();
  await expect(card).toContainText(`${(bench.simulated.asr.alertlens * 100).toFixed(1)}%`, { timeout: 30_000 });
});

test("no horizontal scrolling on a phone", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await page.evaluate(() => window.scrollTo(300, 0));
  expect(await page.evaluate(() => window.scrollX)).toBe(0);
});
