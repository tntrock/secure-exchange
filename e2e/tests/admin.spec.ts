import type { Page, PlaywrightWorkerArgs } from "@playwright/test";
import { readFileSync } from "node:fs";
import { BASE_URL, getRules, saveRules } from "../helpers/api";
import { expect, test, type Staff } from "../helpers/fixtures";
import { makePdf } from "../helpers/files";
import { extractCode, extractLink, waitForMail } from "../helpers/mail";

// Runs in the "admin" Playwright project, after every other spec: the rules test changes site-wide rules.
test.describe.configure({ mode: "serial" });

const row = (page: Pick<Page, "getByRole">, text: string) => page.getByRole("row").filter({ hasText: text });

// createShare uploads a PDF as `owner` and shares it to `recipient`; returns the file name and the share page URL.
async function createShare(owner: Staff, recipient: string, tag: string, allowDownload: boolean) {
  const name = `${tag}.pdf`;
  await owner.page.locator('input[type="file"]').setInputFiles({ name, mimeType: "application/pdf", buffer: makePdf() });
  await expect(row(owner.page, name)).toContainText("Ready", { timeout: 120_000 });
  await owner.page.getByRole("checkbox", { name }).check();
  await owner.page.getByRole("button", { name: /^Create share/ }).click();
  const dlg = owner.page.getByRole("dialog", { name: "Create share" });
  await dlg.getByLabel(/^Recipients/).fill(recipient);
  if (allowDownload) await dlg.getByLabel("Allow download").check();
  else await dlg.getByLabel("Allow download").uncheck();
  await dlg.getByRole("button", { name: "Create", exact: true }).click();
  await expect(owner.page).toHaveURL(/\/shares\/[^/]+$/);
  return { name, url: owner.page.url() };
}

test.describe("site rules", () => {
  let original: Record<string, unknown>;
  const admin = (playwright: PlaywrightWorkerArgs["playwright"]) =>
    playwright.request.newContext({ baseURL: BASE_URL, ignoreHTTPSErrors: true, storageState: JSON.parse(process.env.E2E_ADMIN_STATE!), extraHTTPHeaders: { "X-Forwarded-For": "10.1.2.3" } });

  test.beforeAll(async ({ playwright }) => {
    const a = await admin(playwright);
    original = await getRules(a);
    await a.dispose();
  });
  // restore the exact rules we found, even when the test failed half way
  test.afterAll(async ({ playwright }) => {
    const a = await admin(playwright);
    await saveRules(a, original);
    await a.dispose();
  });

  test("forbid download turns an allow-download share view-only", async ({ staff, adminPage, uniqueEmail, newContext }) => {
    test.setTimeout(240_000);
    const owner = await staff("rulesowner");
    const recipient = uniqueEmail("rulesrecipient");
    const since = new Date();
    const share = await createShare(owner, recipient, "rules-" + Date.now(), true);

    // recipient opens it: Download is offered
    const invite = await waitForMail(recipient, { since, subject: /securely shared|安全分享/ });
    const rp = await (await newContext()).newPage();
    await rp.goto(extractLink(invite.text, /^\/s\//));
    await rp.getByLabel("Your email").fill(recipient);
    const beforeCode = new Date();
    await rp.getByRole("button", { name: "Send code" }).click();
    const codeMail = await waitForMail(recipient, { since: beforeCode, subject: /verification code|驗證碼/ });
    await rp.getByLabel("6-digit code").fill(extractCode(codeMail.text));
    await rp.getByRole("button", { name: "Verify" }).click();
    await expect(row(rp, share.name).getByRole("link", { name: "Download" })).toBeVisible();

    // admin turns the rule on through the UI
    await adminPage.goto("/admin/rules");
    await adminPage.getByLabel("Forbid downloads (view only)").check();
    await adminPage.getByRole("button", { name: "Save", exact: true }).click();
    await expect(adminPage.getByRole("status")).toContainText("Saved.");

    // recipient: view-only now, still can view
    await rp.reload();
    await expect(rp.getByText("Recipients can only view the files in the browser")).toBeVisible();
    await expect(row(rp, share.name).getByRole("button", { name: "View" })).toBeVisible();
    await expect(rp.getByRole("link", { name: "Download" })).toHaveCount(0);

    // owner's share detail: download off, with the administrator-rule note
    await owner.page.goto(share.url);
    const li = owner.page.getByRole("listitem").filter({ hasText: "Allow download:" });
    await expect(li).toContainText("No");
    await expect(li).toContainText("Changed by an administrator rule");
  });
});

test("users: invite a staff user, then disable an active one", async ({ adminPage, staff, uniqueEmail }) => {
  const invited = uniqueEmail("invitee");
  await adminPage.goto("/admin/users");
  await adminPage.getByLabel("Email", { exact: true }).fill(invited);
  await adminPage.getByLabel("Display name").fill("Invitee");
  await adminPage.getByRole("button", { name: "Create and invite" }).click();
  await expect(row(adminPage, invited)).toContainText("Invited");

  const victim = await staff("victim");
  await adminPage.reload();
  adminPage.on("dialog", (d) => void d.accept());
  await expect(row(adminPage, victim.email)).toContainText("Active");
  await row(adminPage, victim.email).getByRole("button", { name: "Disable" }).click();
  await expect(row(adminPage, victim.email)).toContainText("Disabled");

  await victim.page.goto("/files");
  await expect(victim.page).toHaveURL(/\/login$/);
});

test("audit: filter, CSV export, hash chain verify", async ({ adminPage, staff }, testInfo) => {
  const u = await staff("audited"); // makes sure auth.login.ok rows exist
  await adminPage.goto("/admin/audit");
  await adminPage.getByLabel("Action", { exact: true }).fill("auth.login.ok");
  await adminPage.getByRole("button", { name: "Filter", exact: true }).click();
  const body = adminPage.locator("tbody tr");
  await expect(body.first()).toBeVisible();
  await expect(body.first().getByRole("cell").nth(3)).toHaveText("auth.login.ok");
  await expect(body.filter({ hasNot: adminPage.getByRole("cell", { name: "auth.login.ok", exact: true }) })).toHaveCount(0);
  await expect(adminPage.getByText(u.email).first()).toBeVisible();

  const dl = adminPage.waitForEvent("download");
  await adminPage.getByRole("link", { name: "Export CSV" }).click();
  const file = testInfo.outputPath("audit.csv");
  await (await dl).saveAs(file);
  const lines = readFileSync(file, "utf8").replace(/^﻿/, "").split(/\r?\n/);
  expect(lines[0]).toMatch(/^id,/);
  expect(lines[0]).toContain("action");
  expect(lines.length).toBeGreaterThan(2);

  await adminPage.getByRole("button", { name: "Verify hash chain" }).click();
  await expect(adminPage.getByRole("status")).toContainText("hash chain intact");
});

test("all shares: a new share is listed and its detail opens", async ({ adminPage, staff, uniqueEmail }) => {
  test.setTimeout(240_000);
  const owner = await staff("sharesowner");
  await createShare(owner, uniqueEmail("allsharesrcpt"), "all-" + Date.now(), false);
  await adminPage.goto("/admin/shares");
  await adminPage.getByRole("searchbox", { name: "Search by owner email" }).fill(owner.email);
  await adminPage.getByRole("button", { name: "Search", exact: true }).click();
  const r = row(adminPage, owner.email);
  await expect(r).toHaveCount(1);
  await r.getByRole("link").click();
  await expect(adminPage).toHaveURL(/\/admin\/shares\/[^/]+$/);
  await expect(adminPage.getByRole("heading", { name: "Share details" })).toBeVisible();
  await expect(adminPage.getByText(`Owner: ${owner.email}`)).toBeVisible();
});
