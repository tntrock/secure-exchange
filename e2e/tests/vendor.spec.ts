import { readFileSync } from "node:fs";
import type { Locator, Page } from "@playwright/test";
import { expect, test } from "../helpers/fixtures";
import { makePdf } from "../helpers/files";
import { extractLink, waitForMail } from "../helpers/mail";
import { secretFromOtpauth, totp } from "../helpers/totp";

test("vendor lifecycle: invite → approve → enrol → share → upload → disable", async ({ staff, adminPage, uniqueEmail, newContext }, testInfo) => {
  test.setTimeout(8 * 60_000);
  const owner = await staff("vendorhost");
  const vendor = uniqueEmail("vendor");
  const vendorName = "Vee Vendor";
  const vendorPassword = `E2e-${crypto.randomUUID()}`;
  const row = (page: Pick<Page, "getByRole"> | Locator, text: string) => page.getByRole("row").filter({ hasText: text });

  // 1. staff invites the vendor; with the default SX_VENDOR_CREATION=approval it waits for an admin
  await owner.page.goto("/vendors");
  await owner.page.getByLabel("Email", { exact: true }).fill(vendor);
  await owner.page.getByLabel("Display name").fill(vendorName);
  const created = new Date();
  await owner.page.getByRole("button", { name: "Create and invite" }).click();
  await expect(row(owner.page, vendor)).toContainText("Pending approval");

  await adminPage.goto("/vendors");
  const pending = adminPage.getByRole("region", { name: "Pending approval" });
  await row(pending, vendor).getByRole("button", { name: "Approve" }).click();
  await expect(row(adminPage, vendor)).toContainText("Invited");

  // 2. vendor: invite link, password, TOTP (secret taken from the invite lookup the page makes)
  const invite = await waitForMail(vendor, { since: created, subject: /invited|受邀/ });
  const vp = await (await newContext()).newPage();
  const info = vp.waitForResponse((r) => r.url().includes("/api/invite/") && r.request().method() === "GET");
  await vp.goto(extractLink(invite.text, /^\/invite\//));
  const secret = secretFromOtpauth(((await (await info).json()) as { otpauth_url: string }).otpauth_url);
  expect(secret).not.toBe("");
  await vp.getByLabel("Password", { exact: true }).fill(vendorPassword);
  await vp.getByLabel("Confirm password").fill(vendorPassword);
  const success = vp.getByText(/Your account is active/);
  await expect(async () => {
    if (await success.isVisible()) return; // an earlier attempt went through
    await vp.getByLabel("Code (6 digits)").fill(totp(secret));
    await vp.getByRole("button", { name: "Activate account" }).click();
    await expect(success).toBeVisible({ timeout: 5_000 });
  }).toPass({ timeout: 30_000 });

  // 3. vendor signs in (next step's code: the activation code cannot be reused) and lands on /vendor/shares
  await vp.getByRole("link", { name: "Log in" }).click();
  await vp.getByLabel("Email").fill(vendor);
  await vp.getByLabel("Password").fill(vendorPassword);
  await vp.getByRole("button", { name: "Log in" }).click();
  await expect(async () => {
    if (/\/vendor\/shares$/.test(vp.url())) return; // an earlier attempt navigated
    await vp.getByLabel("Code (6 digits)").fill(totp(secret, Date.now() + 30_000));
    await vp.getByRole("button", { name: "Verify" }).click();
    await expect(vp).toHaveURL(/\/vendor\/shares$/, { timeout: 5_000 });
  }).toPass({ timeout: 30_000 });
  await expect(vp.getByRole("heading", { name: "Shared with me" })).toBeVisible();

  // 4. staff shares a PDF with the vendor; the vendor sees and downloads it
  const pdf = `vendor-${testInfo.testId}.pdf`;
  await owner.page.goto("/files");
  await owner.page.locator('input[type="file"]').setInputFiles({ name: pdf, mimeType: "application/pdf", buffer: makePdf() });
  await expect(row(owner.page, pdf)).toContainText("Ready", { timeout: 120_000 });
  await owner.page.getByRole("checkbox", { name: pdf }).check();
  await owner.page.getByRole("button", { name: /^Create share/ }).click();
  const dlg = owner.page.getByRole("dialog", { name: "Create share" });
  await dlg.getByLabel(vendor).check();
  await dlg.getByLabel("Allow download").check();
  await dlg.getByRole("button", { name: "Create", exact: true }).click();
  await expect(owner.page).toHaveURL(/\/shares\/[^/]+$/);

  await vp.goto("/vendor/shares");
  await row(vp, "vendorhost").getByRole("link", { name: "Open" }).click();
  const dl = vp.waitForEvent("download");
  await row(vp, pdf).getByRole("link", { name: "Download" }).click();
  const got = testInfo.outputPath(pdf);
  await (await dl).saveAs(got);
  // recipient downloads are marked (pdf_meta writes the tracking code into the PDF), so bytes differ from the upload
  expect(readFileSync(got).subarray(0, 5).toString()).toBe("%PDF-");

  // 5. vendor uploads to the staff who created the account; staff sees it after the scan
  const name = `from-vendor-${testInfo.testId}.txt`;
  await vp.goto("/vendor/upload");
  await vp.getByLabel("Recipient").selectOption({ label: `vendorhost (${owner.email})` });
  await vp.locator('input[type="file"]').setInputFiles({ name, mimeType: "text/plain", buffer: Buffer.from(`vendor upload ${testInfo.testId}\n`) });
  await expect(vp.getByText("Upload complete").first()).toBeVisible({ timeout: 60_000 });
  await owner.page.goto("/files");
  await expect(
    row(owner.page, name).getByText("No virus found"),
    "ClamAV did not report the vendor upload clean within 5 minutes",
  ).toBeVisible({ timeout: 5 * 60_000 });
  await expect(row(owner.page, name)).toContainText(vendor);

  // 6. staff disables the vendor; the vendor's next navigation goes to /login
  await owner.page.goto("/vendors");
  await row(owner.page, vendor).getByRole("button", { name: "Disable" }).click();
  await expect(row(owner.page, vendor)).toContainText("Disabled");
  await vp.goto("/vendor/shares");
  await expect(vp).toHaveURL(/\/login$/);
});
