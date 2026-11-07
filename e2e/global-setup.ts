import { request } from "@playwright/test";
import { BASE_URL, loginApi } from "./helpers/api";
import { clientIp } from "./helpers/fixtures";

// One admin login per run, shared by every worker through E2E_ADMIN_STATE: the server allows
// 5 password attempts per email (then one per 12 s), so per-worker or per-test admin logins would 429.
export default async function globalSetup() {
  const email = process.env.E2E_ADMIN_EMAIL, password = process.env.E2E_ADMIN_PASSWORD;
  if (!email || !password) throw new Error("E2E_ADMIN_EMAIL / E2E_ADMIN_PASSWORD unset: run through scripts/e2e.sh");
  const ctx = await request.newContext({ baseURL: BASE_URL, ignoreHTTPSErrors: true, extraHTTPHeaders: { "X-Forwarded-For": clientIp() } });
  await loginApi(ctx, email, password);
  process.env.E2E_ADMIN_STATE = JSON.stringify(await ctx.storageState());
  await ctx.dispose();
}
