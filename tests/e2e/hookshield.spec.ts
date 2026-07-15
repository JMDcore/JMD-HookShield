import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

test("has no automatically detectable serious accessibility violations", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Deliveries", exact: true })).toBeVisible();
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(results.violations.filter((violation) => ["serious", "critical"].includes(violation.impact ?? "")))
    .toEqual([]);
});

test("creates an endpoint and demonstrates validation, tampering, duplication, rotation, and timeline", async ({ page }) => {
  const endpointName = `E2E deployment gate ${Date.now()}`;
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Deliveries", exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Create endpoint", exact: true }).click();
  const createDialog = page.getByRole("dialog", { name: "Create endpoint" });
  await createDialog.getByLabel("Endpoint name").fill(endpointName);
  await createDialog.getByLabel("Provider").selectOption("generic");
  await createDialog.getByLabel("Webhook secret").fill("e2e-secret-with-sufficient-entropy");
  await createDialog.getByRole("button", { name: "Create endpoint", exact: true }).click();
  await expect(page.getByText("Endpoint created", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: `${endpointName} Generic HMAC Enabled`, exact: true }).click();
  await page.getByRole("button", { name: "Simulate", exact: true }).click();
  let simulator = page.getByRole("dialog", { name: "Webhook simulator" });
  await simulator.getByRole("combobox", { name: "Target endpoint" }).selectOption({ label: `${endpointName} · Generic HMAC` });
  await simulator.getByRole("button", { name: "Send event", exact: true }).click();
  await expect(page.getByText("Accepted delivery generated", { exact: true })).toBeVisible();
  await expect(page.getByText("Request admitted", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Simulate", exact: true }).click();
  simulator = page.getByRole("dialog", { name: "Webhook simulator" });
  await simulator.getByRole("combobox", { name: "Target endpoint" }).selectOption({ label: `${endpointName} · Generic HMAC` });
  await simulator.getByRole("radio", { name: "Tampered payload Body is changed after signing" }).check();
  await simulator.getByRole("button", { name: "Send event", exact: true }).click();
  await expect(page.getByText("Rejected delivery generated", { exact: true })).toBeVisible();
  await expect(page.getByText("SIGNATURE_INVALID", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Simulate", exact: true }).click();
  simulator = page.getByRole("dialog", { name: "Webhook simulator" });
  await simulator.getByRole("combobox", { name: "Target endpoint" }).selectOption({ label: `${endpointName} · Generic HMAC` });
  await simulator.getByRole("radio", { name: "Duplicate delivery A valid delivery ID is sent twice" }).check();
  await simulator.getByRole("button", { name: "Send event", exact: true }).click();
  await expect(page.getByText("Duplicate delivery generated", { exact: true })).toBeVisible();
  await expect(page.getByText("DUPLICATE_DELIVERY", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Rotate secret", exact: true }).click();
  const rotateDialog = page.getByRole("dialog", { name: "Rotate webhook secret" });
  await rotateDialog.getByLabel("New secret").fill("rotated-e2e-secret-with-sufficient-entropy");
  await rotateDialog.getByLabel("Transition window").selectOption("3600");
  await rotateDialog.getByRole("button", { name: "Rotate secret", exact: true }).click();
  await expect(page.getByText("Secret rotated; previous version remains in transition", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Simulate", exact: true }).click();
  simulator = page.getByRole("dialog", { name: "Webhook simulator" });
  await simulator.getByRole("combobox", { name: "Target endpoint" }).selectOption({ label: `${endpointName} · Generic HMAC` });
  await simulator.getByRole("radio", { name: "Valid after rotation Rotate to a new secret and sign with the active version" }).check();
  await simulator.getByRole("button", { name: "Send event", exact: true }).click();
  await expect(page.getByText("Accepted delivery generated", { exact: true })).toBeVisible();

  await page.getByRole("tab", { name: "Timeline", exact: true }).click();
  await expect(page.getByText("Processing attempt 1", { exact: true })).toBeVisible();
  await expect(page.getByText("Raw bytes captured before deserialization.", { exact: true })).toBeVisible();

  await page.getByRole("tab", { name: "Logs", exact: true }).click();
  await expect(page.getByLabel("Structured delivery logs").getByText("security.decision status=accepted code=none", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Endpoint settings", exact: true }).click();
  const settingsDialog = page.getByRole("dialog", { name: "Endpoint settings" });
  await settingsDialog.getByLabel("Retention days").fill("7");
  const policyResponsePromise = page.waitForResponse((response) =>
    response.url().includes("/api/endpoints/") && response.request().method() === "PATCH"
  );
  await settingsDialog.getByRole("button", { name: "Save policy", exact: true }).click();
  const policyResponse = await policyResponsePromise;
  expect(policyResponse.status(), await policyResponse.text()).toBe(200);
  await expect(page.getByText("Endpoint policy updated", { exact: true })).toBeVisible();
});
