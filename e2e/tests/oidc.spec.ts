import { test, expect } from "../helpers/fixtures";

// The static Dex user (e2e/dex/config.yaml). Fixed by the IdP config, so not unique per test; repeated
// sign-ins map to the same external account (same subject), which is fine.
const OIDC_EMAIL = "oidc-user@e2e.test";
const OIDC_PASSWORD = "e2e-oidc-password";

test("OIDC sign-in via Dex lands on /files as the external account", async ({ page }) => {
  await page.goto("/login");
  const sso = page.getByRole("link", { name: "Sign in with Dex" });
  await expect(sso).toBeVisible();

  await sso.click();
  await expect(page).toHaveURL(/^https:\/\/dex\.localhost:59556\/dex\//);
  await page.getByLabel("Email Address").fill(OIDC_EMAIL);
  await page.getByLabel("Password").fill(OIDC_PASSWORD);
  await page.getByRole("button", { name: "Login" }).click();

  await expect(page).toHaveURL(/localhost:59443\/files$/);
  await expect(page.getByRole("button", { name: "Log out" })).toBeVisible();
  const me = await (await page.request.get("/api/me")).json();
  expect(me).toMatchObject({ email: OIDC_EMAIL, auth_source: "oidc" });
  // external accounts get their second factor from the IdP: no TOTP settings link
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  await expect(page.getByRole("link", { name: "Two-factor settings" })).toHaveCount(0);

  await page.getByRole("button", { name: "Log out" }).click();
  await expect(page).toHaveURL(/\/login$/);
  await page.goto("/files");
  await expect(page).toHaveURL(/\/login$/);
});
