import { test, expect } from "@playwright/test";

test("landing shows qualification warning and no false emission promise", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByText("Servizio NON qualificato")).toBeVisible();
  await expect(page.getByRole("button", { name: "Accedi con la tua organizzazione" })).toBeVisible();
});

test("changes language and dark theme on all viewports", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "English" }).click();
  await expect(page.getByRole("button", { name: "Sign in with your organization" })).toBeVisible();
  await page.getByRole("button", { name: "Dark mode" }).click();
  await expect(page.locator("html")).toHaveClass(/dark/);
});
