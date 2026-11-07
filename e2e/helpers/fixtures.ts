import { test as base, expect, type APIRequestContext, type BrowserContext, type BrowserContextOptions, type Page } from "@playwright/test";
import { activate, activateInfo, BASE_URL, clientIp, createUser, loginApi } from "./api";
import { extractLink, waitForMail } from "./mail";
import { secretFromOtpauth, totp } from "./totp";

// English UI for every page unless a test picked a language itself (the language-switch test).
const english = () => { if (!localStorage.getItem("sx_lang")) localStorage.setItem("sx_lang", "en"); };

export interface Staff { page: Page; email: string; password: string; totpSecret?: string }

type Fixtures = {
  adminApi: APIRequestContext; // signed-in admin API context (shared session, never log it out)
  adminPage: Page; // a signed-in admin page on /files, in its own browser context
  staff: (name: string) => Promise<Staff>;
  uniqueEmail: (tag: string) => string;
  newContext: (opts?: BrowserContextOptions) => Promise<BrowserContext>;
};

const adminState = () => JSON.parse(process.env.E2E_ADMIN_STATE ?? "null") ?? undefined;

export const test = base.extend<Fixtures>({
  extraHTTPHeaders: async ({}, use) => use({ "X-Forwarded-For": clientIp() }),

  context: async ({ context }, use) => {
    await context.addInitScript(english);
    await use(context);
  },

  newContext: async ({ browser, extraHTTPHeaders }, use) => {
    const made: BrowserContext[] = [];
    await use(async (opts = {}) => {
      const c = await browser.newContext({ baseURL: BASE_URL, ignoreHTTPSErrors: true, locale: "en-US", extraHTTPHeaders, ...opts });
      await c.addInitScript(english);
      made.push(c);
      return c;
    });
    for (const c of made) await c.close();
  },

  adminApi: async ({ playwright, extraHTTPHeaders }, use) => {
    const r = await playwright.request.newContext({ baseURL: BASE_URL, ignoreHTTPSErrors: true, extraHTTPHeaders, storageState: adminState() });
    await use(r);
    await r.dispose();
  },

  adminPage: async ({ newContext }, use) => {
    const page = await (await newContext({ storageState: adminState() })).newPage();
    await page.goto("/files");
    await expect(page).toHaveURL(/\/files$/);
    await use(page);
  },

  uniqueEmail: async ({}, use, info) => {
    let n = 0;
    await use((tag) => `${tag.toLowerCase().replace(/[^a-z0-9]+/g, "-")}-${info.testId}-${info.repeatEachIndex}-${Date.now()}-${n++}@e2e.test`);
  },

  // staff(name): invite a local staff account as the admin, activate it from the mailed link (with TOTP
  // when the site forces it), sign in, and return the signed-in page on /files.
  staff: async ({ adminApi, newContext, uniqueEmail }, use) => {
    await use(async (name) => {
      const email = uniqueEmail(name);
      const password = `E2e-${crypto.randomUUID()}`;
      const since = new Date();
      await createUser(adminApi, email, name);
      const mail = await waitForMail(email, { since, subject: /invited|受邀/ });
      const token = extractLink(mail.text, /^\/activate\//).split("/").pop()!;
      const ctx = await newContext();
      const info = await activateInfo(ctx.request, token);
      const totpSecret = info.totp_required ? secretFromOtpauth(info.otpauth_url) : undefined;
      await activate(ctx.request, token, password, totpSecret ? totp(totpSecret) : "");
      await loginApi(ctx.request, email, password, totpSecret);
      const page = await ctx.newPage();
      await page.goto("/files");
      await expect(page).toHaveURL(/\/files$/);
      return { page, email, password, totpSecret };
    });
  },
});

export { expect };
