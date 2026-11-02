import { readFileSync } from "node:fs";
import { expect, test } from "@playwright/test";

test("actual workflow, negative controls, audit trail and responsive view", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  const scenario = JSON.parse(readFileSync("samples/scenario.json", "utf8"));
  await page.goto("/");
  await expect(page.locator("#run")).toBeEnabled();
  for (let i = 0; i < scenario.steps.length; i++) {
    await page.locator("#run").click();
    await expect(page.locator("#progress")).toHaveText(
      `${i + 1} / ${scenario.steps.length} completed`,
    );
    await expect(page.locator("#decision")).toContainText(
      scenario.steps[i].expect_error ? "Expected denial verified" : "Operation verified",
    );
  }
  await page.locator("#evidence").click();
  await expect(page.locator("#decision")).toHaveText("Audit chain verified");
  await expect(page.locator("#output")).toContainText("verified_local_chain");
  await page.screenshot({ path: "docs/workbench.png", fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
  ).toBeTruthy();
  expect(errors).toEqual([]);
});
