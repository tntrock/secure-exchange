import { test, expect } from "../helpers/fixtures";
import type { Page } from "@playwright/test";

async function signIn(page: Page, email: string, password: string) {
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Log in" }).click();
}

test("admin signs in and lands on /files", async ({ page }) => {
  await page.goto("/login");
  await signIn(page, process.env.E2E_ADMIN_EMAIL!, process.env.E2E_ADMIN_PASSWORD!);
  await expect(page).toHaveURL(/\/files$/);
  await expect(page.getByRole("button", { name: "Log out" })).toBeVisible();
});

test("a wrong password shows the invalid message", async ({ page, staff }) => {
  const { email } = await staff("wrongpw");
  await page.goto("/login");
  await signIn(page, email, "not-the-password-123");
  await expect(page.getByRole("alert")).toHaveText("Invalid email or password");
  await expect(page).toHaveURL(/\/login$/);
});

test("sign out returns to /login and ends the session", async ({ staff }) => {
  const { page } = await staff("signout");
  await page.getByRole("button", { name: "Log out" }).click();
  await expect(page).toHaveURL(/\/login$/);
  await page.goto("/files");
  await expect(page).toHaveURL(/\/login$/);
});

test("the language switch changes the login page and back", async ({ page }) => {
  await page.goto("/login");
  await expect(page.getByRole("button", { name: "Log in" })).toBeVisible();
  const lang = page.getByRole("combobox");
  await lang.selectOption({ label: "繁體中文" });
  await expect(page.getByRole("button", { name: "登入" })).toBeVisible();
  await lang.selectOption({ label: "English" });
  await expect(page.getByRole("button", { name: "Log in" })).toBeVisible();
});

test("a signed-out deep link returns to it after sign-in", async ({ page, staff }) => {
  const { email, password } = await staff("deeplink");
  await page.goto("/shares");
  await expect(page).toHaveURL(/\/login$/);
  await signIn(page, email, password);
  await expect(page).toHaveURL(/\/shares$/);
});
