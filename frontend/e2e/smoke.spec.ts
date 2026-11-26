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
  await page.getByRole("button", { name: "Investigate" }).click();
  await expect(page).toHaveURL(/investigations\//);
  await expect(page.getByText("Pipeline")).toBeVisible();
});
test("rejects bad login", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel("Email").fill("nobody@example.com");
  await page.getByLabel("Password").fill("wrong-password-1");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("alert")).toContainText("Incorrect email or password");
});
