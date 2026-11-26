import { test, expect } from "@playwright/test";
// Requires: backend on :8000 (in-memory store is fine) and `npm run dev`. Neo4j is optional: graph/explorer show an error state without it.
const email = `e2e${Date.now()}@example.com`;
test("register, greeting, first query is centered, investigation runs", async ({ page }) => {
  await page.goto("/register");
  await page.getByLabel("Name").fill("E2E Analyst");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill("correct-horse-1");
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page.getByRole("heading", { name: /Good (morning|afternoon|evening), E2E/ })).toBeVisible();
  await page.getByPlaceholder(/Ask a threat intelligence question/).fill("Which techniques does APT28 use?");
  const box = await page.getByPlaceholder(/Ask a threat intelligence question/).boundingBox();
  const vh = page.viewportSize()!.height;
  expect(box!.y + box!.height / 2).toBeGreaterThan(vh * 0.3); // first question: composer is in the middle of the page
  expect(box!.y + box!.height / 2).toBeLessThan(vh * 0.7);
  await page.getByRole("button", { name: "Send" }).click();
  await expect(page).toHaveURL(/\/chat\//);
  await expect(page.getByText("Pipeline")).toBeVisible();
  const docked = await page.getByPlaceholder(/Wait for the current|Ask another question/).boundingBox();
  expect(docked!.y).toBeGreaterThan(vh * 0.7); // later questions: composer is docked at the bottom
});
test("a chat holds several questions and the page has no extra scrollbars", async ({ page }) => {
  test.setTimeout(240000);
  await page.goto("/register");
  await page.getByLabel("Name").fill("E2E Analyst");
  await page.getByLabel("Email").fill(`e2e2${Date.now()}@example.com`);
  await page.getByLabel("Password").fill("correct-horse-1");
  await page.getByRole("button", { name: "Create account" }).click();
  await page.getByPlaceholder(/Ask a threat intelligence question/).fill("Which techniques does APT28 use?");
  await page.getByRole("button", { name: "Send" }).click();
  await expect(page.getByRole("button", { name: "Send" })).toBeEnabled({ timeout: 120000 });
  await page.getByPlaceholder(/Ask another question/).fill("What is known about CVE-2023-23397?");
  await page.getByRole("button", { name: "Send" }).click();
  await expect(page.locator(".bubble")).toHaveCount(2, { timeout: 120000 });
  await expect(page).toHaveURL(/\/chat\/c_/);
  const overflow = await page.evaluate(() => ({ x: document.documentElement.scrollWidth > innerWidth, y: document.documentElement.scrollHeight > innerHeight }));
  expect(overflow).toEqual({ x: false, y: false });
});
test("rejects bad login", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel("Email").fill("nobody@example.com");
  await page.getByLabel("Password").fill("wrong-password-1");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("alert")).toContainText("Incorrect email or password");
});
