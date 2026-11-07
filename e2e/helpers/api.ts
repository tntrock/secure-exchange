import type { APIRequestContext } from "@playwright/test";
import { totp } from "./totp";

export const BASE_URL = process.env.E2E_BASE_URL ?? "https://localhost:59443";
// the server's cross-origin protection wants a same-origin Origin on state-changing calls (as smoke.sh sends)
const ORIGIN = { Origin: BASE_URL };

// apiCall sends one JSON API request with the context's cookies and returns the parsed body
// (undefined for 204). Throws with the status and body on anything but 2xx.
export async function apiCall<T = unknown>(request: APIRequestContext, method: string, path: string, body?: unknown): Promise<T> {
  const r = await request.fetch(BASE_URL + path, { method, headers: ORIGIN, data: body });
  if (!r.ok()) throw new Error(`${method} ${path}: ${r.status()} ${await r.text()}`);
  return (r.status() === 204 ? undefined : await r.json()) as T;
}

// loginApi signs `request` in with a password (and the TOTP step when the account has it).
// A login that still has to enrol TOTP (force_totp on, account without TOTP) throws.
// The TOTP code is the next step's: the server accepts it, and it never replays a code just used
// (e.g. at activation), since each step is accepted once.
export async function loginApi(request: APIRequestContext, email: string, password: string, totpSecret?: string): Promise<void> {
  const r = await apiCall<{ mfa_required: boolean; totp_setup_required?: boolean }>(request, "POST", "/api/auth/login", { email, password });
  if (r.totp_setup_required) throw new Error(`${email} must enrol TOTP first`);
  if (!r.mfa_required) return;
  if (!totpSecret) throw new Error(`${email} has TOTP but no secret was given`);
  await apiCall(request, "POST", "/api/auth/totp", { code: totp(totpSecret, Date.now() + 30_000) });
}

export interface UserInfo { id: string; email: string; role: string; status: string; totp_enabled: boolean }

// createUser invites a local staff or admin account (admin session); the activation link goes out by mail.
export const createUser = (admin: APIRequestContext, email: string, display_name: string, role: "staff" | "admin" = "staff") =>
  apiCall<UserInfo>(admin, "POST", "/api/admin/users", { email, display_name, role });

export const activateInfo = (request: APIRequestContext, token: string) =>
  apiCall<{ email: string; totp_required: boolean; otpauth_url: string }>(request, "GET", `/api/activate/${encodeURIComponent(token)}`);

export const activate = (request: APIRequestContext, token: string, password: string, code = "") =>
  apiCall<void>(request, "POST", `/api/activate/${encodeURIComponent(token)}`, { password, code });

export const getRules = (request: APIRequestContext) => apiCall<Record<string, unknown>>(request, "GET", "/api/rules");
export const saveRules = (admin: APIRequestContext, rules: Record<string, unknown>) => apiCall(admin, "PUT", "/api/admin/rules", rules);
