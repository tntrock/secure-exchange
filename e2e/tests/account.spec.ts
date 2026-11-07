import { expect, test } from "../helpers/fixtures";
import { secretFromOtpauth, totp } from "../helpers/totp";

test("enrol TOTP, sign out, sign back in with password + code", async ({ staff }) => {
  const u = await staff("totpuser");
  const { page } = u;
  await page.goto("/settings/totp");
  // the page only draws a QR code; take the secret from the setup response
  const setup = page.waitForResponse((r) => r.url().endsWith("/api/me/totp/setup") && r.request().method() === "POST");
  await page.getByRole("button", { name: "Start setup" }).click();
  const secret = secretFromOtpauth(((await (await setup).json()) as { otpauth_url: string }).otpauth_url);
  expect(secret).not.toBe("");
  await expect(page.getByRole("img", { name: "Two-factor authentication QR code" })).toBeVisible();
  // a code at a step boundary can be rejected: retry with a fresh one
  await expect(async () => {
    if (await page.getByText("Two-factor authentication is enabled").isVisible()) return; // an earlier attempt went through
    await page.getByLabel("Code").fill(totp(secret));
    await page.getByRole("button", { name: "Enable" }).click();
    await expect(page.getByText("Two-factor authentication is enabled")).toBeVisible({ timeout: 5_000 });
  }).toPass({ timeout: 30_000 });

  await page.getByRole("button", { name: "Log out" }).click();
  await expect(page).toHaveURL(/\/login$/);
  await page.getByLabel("Email").fill(u.email);
  await page.getByLabel("Password").fill(u.password);
  await page.getByRole("button", { name: "Log in" }).click();
  // next step's code: the enrolment code's step cannot be reused
  await expect(async () => {
    if (/\/files$/.test(page.url())) return; // an earlier attempt navigated
    await page.getByLabel("Code (6 digits)").fill(totp(secret, Date.now() + 30_000));
    await page.getByRole("button", { name: "Verify" }).click();
    await expect(page).toHaveURL(/\/files$/, { timeout: 5_000 });
  }).toPass({ timeout: 30_000 });
});

test("a notification preference saves and persists after reload", async ({ staff }) => {
  const { page } = await staff("prefs");
  await page.goto("/settings");
  const box = page.getByLabel("When a recipient downloads my files");
  await expect(box).toBeVisible();
  const before = await box.isChecked();
  await box.setChecked(!before);
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByRole("status")).toHaveText("Saved.");
  await page.reload();
  await expect(box).toBeChecked({ checked: !before });
});
