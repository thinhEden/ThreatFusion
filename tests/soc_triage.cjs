const assert = require("node:assert/strict");
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || "playwright");
const base = process.env.DASHBOARD_URL || "http://127.0.0.1:8032";
(async () => {
  const browser = await chromium.launch({ headless: true, channel: "msedge" });
  try {
    const page = await browser.newPage({
      viewport: { width: 1440, height: 1000 },
    });
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    await page.goto(base);
    await page
      .getByRole("button", { name: "Investigate PCAP-1003", exact: true })
      .click();
    const drawer = page.getByRole("region", { name: "Alert investigation" });
    await drawer.getByLabel("Status", { exact: true }).selectOption("Closed");
    await drawer.getByRole("button", { name: "Save update" }).click();
    await drawer
      .getByRole("alert")
      .filter({ hasText: "Closing requires" })
      .waitFor();
    await drawer.getByLabel("Assigned to").fill("QA analyst");
    await drawer.getByLabel("Analyst verdict").selectOption("True positive");
    await drawer
      .getByLabel("Investigation note")
      .fill("Verified the out-of-window request against the recorded ticket.");
    await drawer.getByRole("button", { name: "Save update" }).click();
    await page
      .getByRole("status")
      .filter({ hasText: "Analyst update saved" })
      .waitFor();
    await drawer.getByRole("tab", { name: "Activity", exact: true }).click();
    await drawer
      .getByText(
        "Verified the out-of-window request against the recorded ticket.",
        { exact: true },
      )
      .first()
      .waitFor();
    await page.reload();
    await page
      .getByRole("button", { name: "Investigate PCAP-1003", exact: true })
      .click();
    assert.equal(
      await page.getByLabel("Assigned to").inputValue(),
      "QA analyst",
    );
    assert.equal(
      await drawer.getByLabel("Status", { exact: true }).inputValue(),
      "Closed",
    );
    await drawer.getByRole("button", { name: "Create case" }).click();
    const modal = page.getByRole("dialog");
    await modal
      .getByLabel("Case title")
      .fill("QA: unauthorized engineering write");
    await modal.getByLabel("Owner", { exact: true }).fill("QA analyst");
    await modal
      .getByLabel("Note", { exact: true })
      .fill("Created from the packet investigation.");
    await modal
      .getByRole("button", { name: "Create case", exact: true })
      .click();
    await page
      .getByRole("status")
      .filter({ hasText: "Case created" })
      .waitFor();
    await drawer.getByRole("button", { name: "Close investigation" }).click();
    await page
      .getByRole("navigation", { name: "Workspace" })
      .getByRole("button", { name: /^Cases/ })
      .click();
    const caseRow = page
      .getByRole("row")
      .filter({ hasText: "QA: unauthorized engineering write" })
      .first();
    await caseRow.getByRole("button").click();
    await modal.getByLabel("Case status").selectOption("Closed");
    await modal
      .getByLabel("Case update")
      .fill("Evidence recorded; local case review complete.");
    await modal.getByRole("button", { name: "Save case" }).click();
    await modal.waitFor({ state: "hidden" });
    assert.ok((await caseRow.innerText()).includes("Closed"));
    await page
      .getByRole("navigation", { name: "Workspace" })
      .getByRole("button", { name: /^Alert queue/ })
      .click();
    await page
      .locator("input[type=file]")
      .setInputFiles({
        name: "measured-zero.csv",
        mimeType: "text/csv",
        buffer: Buffer.from(
          "event_id,timestamp,src_ip,dst_ip,risk_score,latency_ms,top_severity,protocol,reasons\nzero,2026-09-30T10:00:00Z,172.16.0.1,172.16.0.2,0,0,low,process,Measured zero\n",
        ),
      });
    await page
      .getByRole("button", { name: "Investigate zero", exact: true })
      .click();
    assert.ok((await drawer.innerText()).includes("0 ms"));
    await drawer.getByRole("tab", { name: "Context", exact: true }).click();
    await drawer
      .getByRole("heading", { name: "No linked context audit" })
      .waitFor();
    await drawer.getByRole("button", { name: "Close investigation" }).click();
    await page
      .getByRole("combobox", { name: "Status filter" })
      .selectOption("Closed");
    await page.getByRole("heading", { name: "No matching alerts" }).waitFor();
    await page.getByRole("button", { name: "Reset filters" }).click();
    const download = page.waitForEvent("download");
    await page.getByRole("button", { name: "Export filtered alerts" }).click();
    assert.equal(
      (await download).suggestedFilename(),
      "threatfusion-filtered-alerts.csv",
    );
    await page.route("**/api/workspace?*", (r) =>
      r.fulfill({
        status: 503,
        contentType: "application/json",
        body: '{"error":"Storage temporarily unavailable"}',
      }),
    );
    await page.getByRole("button", { name: "Refresh data" }).click();
    await page
      .getByRole("alert")
      .filter({ hasText: "Storage temporarily unavailable" })
      .waitFor();
    assert.equal(
      await page
        .getByRole("button", { name: "Investigate zero", exact: true })
        .count(),
      1,
    );
    await page.unroute("**/api/workspace?*");
    await page.getByRole("button", { name: "Retry", exact: true }).click();
    await page.getByRole("alert").waitFor({ state: "hidden" });
    assert.deepEqual(errors, []);
    console.log(
      "SOC workflow: closure validation / notes / reload persistence / case lifecycle / CSV import / zeros / export / API error recovery passed",
    );
  } finally {
    await browser.close();
  }
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
