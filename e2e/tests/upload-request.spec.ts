import { readFileSync } from "node:fs";
import { expect, test } from "../helpers/fixtures";
import { extractCode, extractLink, waitForMail } from "../helpers/mail";

test("upload request → external upload → scan → staff download", async ({ staff, uniqueEmail, newContext }, testInfo) => {
  test.setTimeout(8 * 60_000);
  const owner = await staff("requester");
  const uploader = uniqueEmail("uploader");
  const name = `contract-${testInfo.testId}.txt`;
  const content = Buffer.from(`e2e upload ${testInfo.testId} ${Date.now()}\n`);

  // 1. staff creates the request
  const since = new Date();
  await owner.page.goto("/requests");
  await owner.page.getByLabel(/^Uploaders/).fill(uploader);
  await owner.page.getByRole("button", { name: "Create request" }).click();
  await expect(owner.page).toHaveURL(/\/requests\/[^/]+$/);
  const detailUrl = new URL(owner.page.url()).pathname;

  // 2. uploader: link from mail, code from mail, upload
  const invite = await waitForMail(uploader, { since, subject: /asked to upload|請您上傳/ });
  const up = await (await newContext()).newPage();
  await up.goto(extractLink(invite.text, /^\/r\//));
  await up.getByLabel("Your email").fill(uploader);
  const beforeCode = new Date();
  await up.getByRole("button", { name: "Send code" }).click();
  const codeMail = await waitForMail(uploader, { since: beforeCode, subject: /verification code|驗證碼/ });
  await up.getByLabel("6-digit code").fill(extractCode(codeMail.text));
  await up.getByRole("button", { name: "Verify" }).click();
  await up.locator('input[type="file"]').setInputFiles({ name, mimeType: "text/plain", buffer: content });
  await expect(up.getByText("Upload complete").first()).toBeVisible({ timeout: 60_000 });
  await expect(up.getByRole("row").filter({ hasText: name })).toBeVisible();

  // 3. request detail: the file is listed, then the scan finishes clean (page refreshes itself while pending)
  await owner.page.goto(detailUrl);
  const detailRow = owner.page.getByRole("row").filter({ hasText: name });
  await expect(detailRow).toBeVisible();
  await expect(
    detailRow.getByText("No virus found"),
    "ClamAV did not report the uploaded file clean within 5 minutes (still scanning, or scan error?)",
  ).toBeVisible({ timeout: 5 * 60_000 });

  // 4. staff downloads it from My files
  await owner.page.goto("/files");
  const fileRow = owner.page.getByRole("row").filter({ hasText: name });
  await expect(fileRow.getByText("No virus found")).toBeVisible();
  const dl = owner.page.waitForEvent("download");
  await fileRow.getByRole("link", { name: "Download" }).click();
  const path = testInfo.outputPath(name);
  await (await dl).saveAs(path);
  expect(readFileSync(path).equals(content)).toBe(true);
});
