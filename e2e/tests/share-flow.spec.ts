import { readFileSync } from "node:fs";
import { expect, test } from "../helpers/fixtures";
import { makePdf, makePng } from "../helpers/files";
import { extractCode, extractLink, waitForMail } from "../helpers/mail";

test("share → verify → view → download → trace", async ({ staff, uniqueEmail, newContext, adminPage }, testInfo) => {
  test.setTimeout(240_000);
  const owner = await staff("owner");
  const recipient = uniqueEmail("recipient");
  const pdf = `report-${testInfo.testId}.pdf`;
  const png = `photo-${testInfo.testId}.png`;
  const row = (page: typeof owner.page, name: string) => page.getByRole("row").filter({ hasText: name });

  // 1. upload both files and wait for the previews
  await owner.page.locator('input[type="file"]').setInputFiles([
    { name: pdf, mimeType: "application/pdf", buffer: makePdf() },
    { name: png, mimeType: "image/png", buffer: makePng() },
  ]);
  for (const n of [pdf, png]) await expect(row(owner.page, n)).toContainText("Ready", { timeout: 120_000 });

  // 2. share dialog: Esc closes it, reopen, then share
  const since = new Date();
  for (const n of [pdf, png]) await owner.page.getByRole("checkbox", { name: n }).check();
  const open = owner.page.getByRole("button", { name: /^Create share/ });
  await open.click();
  const dlg = owner.page.getByRole("dialog", { name: "Create share" });
  await expect(dlg).toBeVisible();
  await owner.page.keyboard.press("Escape");
  await expect(dlg).toBeHidden();
  await open.click();
  await dlg.getByLabel(/^Recipients/).fill(recipient);
  await dlg.getByLabel("Allow download").check();
  await expect(dlg.getByLabel("Watermark")).toBeChecked();
  await dlg.getByRole("button", { name: "Create", exact: true }).click();
  await expect(owner.page).toHaveURL(/\/shares\/[^/]+$/);

  // 3. recipient in a fresh context: invitation link, code, file list
  const invite = await waitForMail(recipient, { since, subject: /securely shared|安全分享/ });
  const link = extractLink(invite.text, /^\/s\//);
  const rp = await (await newContext()).newPage();
  await rp.goto(link);
  await rp.getByLabel("Your email").fill(recipient);
  const beforeCode = new Date();
  await rp.getByRole("button", { name: "Send code" }).click();
  const codeMail = await waitForMail(recipient, { since: beforeCode, subject: /verification code|驗證碼/ });
  await rp.getByLabel("6-digit code").fill(extractCode(codeMail.text));
  await rp.getByRole("button", { name: "Verify" }).click();
  await expect(rp.getByRole("heading", { name: "Shared files" })).toBeVisible();

  // 4. viewer: page image visible, Esc closes, focus returns to the View button
  const view = row(rp, pdf).getByRole("button", { name: "View" });
  await view.click();
  const viewer = rp.getByRole("dialog", { name: "File viewer" });
  await expect(viewer.getByRole("img", { name: "Page 1" })).toBeVisible();
  await rp.keyboard.press("Escape");
  await expect(viewer).toBeHidden();
  await expect(view).toBeFocused();

  // 5-7. download each file, trace it as admin
  await adminPage.goto("/admin/trace");
  for (const [name, method] of [[pdf, "Watermarked PDF pages"], [png, "Visible + invisible watermark"]]) {
    const dl = rp.waitForEvent("download");
    await row(rp, name).getByRole("link", { name: "Download" }).click();
    const file = testInfo.outputPath(`dl-${name}`);
    await (await dl).saveAs(file);
    expect(readFileSync(file).length).toBeGreaterThan(0);

    await adminPage.getByLabel(/^Suspect file/).setInputFiles(file);
    await adminPage.locator("form").filter({ hasText: "Suspect file" }).getByRole("button", { name: "Search" }).click();
    const hit = adminPage.getByRole("row").filter({ hasText: recipient }).filter({ hasText: method });
    await expect(hit.first()).toBeVisible();
  }
});
