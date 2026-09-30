const assert = require("node:assert/strict");
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "playwright");
const base = process.env.DASHBOARD_URL || "http://127.0.0.1:8031";
(async () => {
  const browser = await chromium.launch({
    headless: true,
    channel: process.env.BROWSER_CHANNEL || "msedge",
  });
  try {
    const page = await browser.newPage({
      viewport: { width: 1440, height: 1000 },
    });
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    const externalRequests = [];
    page.on("request", (request) => {
      if (new URL(request.url()).origin !== new URL(base).origin)
        externalRequests.push(request.url());
    });
    await page.goto(base);
    await page
      .getByRole("button", { name: "Investigate PCAP-1003", exact: true })
      .waitFor();
    await page.screenshot({
      path: "out/soc_queue_desktop.png",
      fullPage: true,
    });
    assert.ok(
      (await page.locator(".queue-caption").innerText()).includes("80"),
    );
    await page
      .getByRole("combobox", { name: "Context filter" })
      .selectOption("suppressed");
    assert.ok(
      (await page.locator(".queue-caption").innerText()).includes("60"),
    );
    await page.getByRole("textbox", { name: "Search alerts" }).fill("PCAP-118");
    await page
      .getByRole("button", { name: "Investigate PCAP-118", exact: true })
      .click();
    await page.getByRole("region", { name: "Alert investigation" }).waitFor();
    await page.getByRole("tab", { name: "Context", exact: true }).click();
    await page.getByText("CHG-OT-2026-001", { exact: true }).waitFor();
    await page.screenshot({
      path: "out/soc_investigation_desktop.png",
      fullPage: true,
    });
    await page.keyboard.press("Escape");
    await page.getByRole("button", { name: "Reset filters" }).click();
    await page
      .getByRole("navigation", { name: "Workspace" })
      .getByRole("button", { name: "Endpoints" })
      .click();
    await page.getByRole("heading", { name: "Observed endpoints" }).waitFor();
    assert.ok(
      (await page
        .locator("canvas")
        .evaluate(
          (c) =>
            new Set(
              c.getContext("2d").getImageData(0, 0, c.width, c.height).data,
            ).size,
        )) > 10,
    );
    await page
      .getByRole("navigation", { name: "Workspace" })
      .getByRole("button", { name: "Evaluation" })
      .click();
    await page
      .getByRole("heading", { name: "Combined Recall: 94.12%" })
      .waitFor();
    await page.getByRole("tab", { name: "Compromised endpoint" }).click();
    await page.screenshot({
      path: "out/soc_evaluation_desktop.png",
      fullPage: true,
    });
    await page
      .getByRole("navigation", { name: "Workspace" })
      .getByRole("button", { name: "Detection rules" })
      .click();
    await page
      .getByRole("button", { name: "Inspect BR-001", exact: true })
      .click();
    await page.getByRole("dialog").waitFor();
    await page.keyboard.press("Escape");
    await page.setViewportSize({ width: 390, height: 844 });
    await page
      .getByRole("combobox", { name: "Workspace view" })
      .selectOption("queue");
    await page.screenshot({ path: "out/soc_queue_mobile.png", fullPage: true });
    assert.equal(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
      true,
    );
    await page
      .getByRole("button", { name: "Investigate PCAP-1003", exact: true })
      .click();
    await page.screenshot({
      path: "out/soc_investigation_mobile.png",
      fullPage: false,
    });
    const panel = await page.locator(".investigation").boundingBox();
    assert.equal(panel.y, 0);
    assert.equal(panel.width, 390);
    assert.equal(panel.height, 844);
    await page.keyboard.press("Escape");
    await page
      .getByLabel("Data source", { exact: true })
      .selectOption("challenge");
    await page
      .getByRole("combobox", { name: "Context filter" })
      .selectOption("all");
    await page
      .getByRole("button", { name: "Investigate PCAP-4", exact: true })
      .waitFor();
    assert.ok((await page.locator(".queue-caption").innerText()).includes("5"));
    await page.getByLabel("Data source", { exact: true }).selectOption("live");
    await page.waitForTimeout(1000);
    assert.equal(
      await page
        .getByText("Recorded lab · synthetic Modbus", { exact: true })
        .count(),
      0,
    );
    assert.deepEqual(errors, []);
    assert.deepEqual(externalRequests, [], "Runtime assets must load locally");
    console.log(
      "SOC UI: queue/filter/evidence/context/navigation/research/rules/source isolation/desktop/mobile passed",
    );
  } finally {
    await browser.close();
  }
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
