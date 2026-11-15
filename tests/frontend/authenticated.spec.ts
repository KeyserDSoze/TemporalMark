import { test, expect } from "@playwright/test";

test("development tenant administrator authenticates and sees own registry", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Accedi con la tua organizzazione" }).click();
  await expect(page).toHaveURL(/localhost:8081/);

  await page.locator("#username").fill("demo-admin");
  await page.locator("#password").fill("local-dev-only");
  await page.locator("#kc-login").click();

  // This tests full OIDC + real database membership, not just a mocked API.
  await expect(page.getByText("11111111-1111-1111-1111-111111111111")).toBeVisible({ timeout: 30000 });
  await expect(page.getByText("Nessuna marca registrata nel periodo selezionato.")).toBeVisible();
  await expect(page.getByText("Servizio NON qualificato")).toBeVisible();

  await page.locator('input[type="file"]').setInputFiles({
    name: "example.txt",
    mimeType: "text/plain",
    buffer: Buffer.from("private local test document")
  });
  await page.getByRole("button", { name: "Richiedi marca esterna" }).click();
  await expect(page.getByText(/Nessuna TSA esterna configurata/)).toBeVisible();
});
