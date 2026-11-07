import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import i18n from "../i18n";
import Vendors from "./Vendors";

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status });
const v = (id: string, status: string, can_manage: boolean, org = "Acme") => ({
  id, email: `${id}@v.com`, display_name: `Name ${id}`, org, status, expires_at: "2030-01-01T00:00:00Z",
  created_by_name: "Sam", created_at: "2029-01-01T00:00:00Z", can_manage,
});

function mockApi(role: string, rows: unknown[], post: Response = json(201, v("new", "invited", true))) {
  const f = vi.fn(async (url: string, init?: RequestInit) => {
    if (url === "/api/me") return json(200, { id: "u", email: "u@x.com", display_name: "U", role, totp_enabled: true });
    if (url === "/api/vendors" && (init?.method ?? "GET") === "GET") return json(200, rows);
    if (init?.method === "POST" && url === "/api/vendors") return post.clone();
    return new Response(null, { status: 204 });
  });
  vi.stubGlobal("fetch", f);
  return f;
}
const renderPage = () => render(<MemoryRouter><Vendors /></MemoryRouter>);
type Call = [string, RequestInit | undefined];
const find = (f: ReturnType<typeof vi.fn>, url: string, method?: string) =>
  (f.mock.calls as Call[]).find((c) => c[0] === url && (method === undefined || c[1]?.method === method));

beforeEach(() => i18n.changeLanguage("en"));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

test("creates a vendor with org and expiry", async () => {
  const f = mockApi("staff", [v("a", "active", false, "Acme")]);
  renderPage();
  await screen.findByText("a@v.com");
  const field = (k: string) => screen.getByLabelText(i18n.t(k)) as HTMLInputElement;
  expect(document.querySelectorAll("datalist option")).toHaveLength(1);
  const exp = field("vendors.expiresOn");
  expect(exp.min < exp.value && exp.value < exp.max).toBe(true);
  fireEvent.change(field("vendors.email"), { target: { value: "n@v.com" } });
  fireEvent.change(field("vendors.name"), { target: { value: "New One" } });
  fireEvent.change(field("vendors.org"), { target: { value: "Globex" } });
  fireEvent.change(exp, { target: { value: exp.max } });
  fireEvent.click(screen.getByRole("button", { name: i18n.t("vendors.create") }));
  await waitFor(() => expect(find(f, "/api/vendors", "POST")).toBeTruthy());
  const body = JSON.parse(find(f, "/api/vendors", "POST")![1]!.body as string);
  expect(body).toMatchObject({ email: "n@v.com", display_name: "New One", org: "Globex" });
  const ms = new Date(body.expires_at).getTime();
  expect(ms).toBeLessThan(Date.now() + 1095 * 864e5);
  expect(ms).toBeGreaterThan(Date.now() + 1090 * 864e5);
});

test("shows approve/reject only to admins", async () => {
  mockApi("staff", [v("p", "pending", false)]);
  renderPage();
  await screen.findByText("p@v.com");
  expect(screen.queryByRole("button", { name: i18n.t("vendors.approve") })).toBeNull();
  cleanup();
  const f = mockApi("admin", [v("p", "pending", true), v("a", "active", true)]);
  renderPage();
  const pending = await screen.findByRole("region", { name: i18n.t("vendors.pendingTitle") });
  fireEvent.click(within(pending).getByRole("button", { name: i18n.t("vendors.approve") }));
  await waitFor(() => expect(find(f, "/api/vendors/p/approve", "POST")).toBeTruthy());
  vi.stubGlobal("confirm", vi.fn(() => false));
  fireEvent.click(within(pending).getByRole("button", { name: i18n.t("vendors.reject") }));
  expect(find(f, "/api/vendors/p/reject")).toBeUndefined();
  vi.stubGlobal("confirm", vi.fn(() => true));
  fireEvent.click(within(pending).getByRole("button", { name: i18n.t("vendors.reject") }));
  await waitFor(() => expect(find(f, "/api/vendors/p/reject", "POST")).toBeTruthy());
});

test("manage actions only when can_manage", async () => {
  const f = mockApi("staff", [v("m", "invited", true), v("n", "active", false), v("d", "disabled", true)]);
  renderPage();
  await screen.findByText("m@v.com");
  const row = (id: string) => screen.getByText(`${id}@v.com`).closest("tr")!;
  expect(within(row("n")).queryByRole("button")).toBeNull();
  expect(within(row("d")).queryByRole("button", { name: i18n.t("vendors.reinvite") })).toBeNull();
  fireEvent.click(within(row("m")).getByRole("button", { name: i18n.t("vendors.disable") }));
  await waitFor(() => expect(find(f, "/api/vendors/m/disable")).toBeTruthy());
  fireEvent.click(within(row("d")).getByRole("button", { name: i18n.t("vendors.enable") }));
  await waitFor(() => expect(find(f, "/api/vendors/d/enable")).toBeTruthy());
  fireEvent.click(within(row("m")).getByRole("button", { name: i18n.t("vendors.reinvite") }));
  await waitFor(() => expect(find(f, "/api/vendors/m/reinvite")).toBeTruthy());
  fireEvent.click(within(row("m")).getByRole("button", { name: i18n.t("vendors.changeExpiry") }));
  fireEvent.change(within(row("m")).getByLabelText(i18n.t("vendors.expiresOn")), { target: { value: "2028-05-06" } });
  fireEvent.click(within(row("m")).getByRole("button", { name: i18n.t("vendors.save") }));
  await waitFor(() => expect(find(f, "/api/vendors/m", "PATCH")).toBeTruthy());
  expect(JSON.parse(find(f, "/api/vendors/m", "PATCH")![1]!.body as string).expires_at).toMatch(/^2028-05-0[67]T/);
});

test("email_taken shows message", async () => {
  mockApi("staff", [], json(409, { error: "email_taken" }));
  renderPage();
  fireEvent.change(await screen.findByLabelText(i18n.t("vendors.email")), { target: { value: "n@v.com" } });
  fireEvent.change(screen.getByLabelText(i18n.t("vendors.name")), { target: { value: "N" } });
  fireEvent.click(screen.getByRole("button", { name: i18n.t("vendors.create") }));
  expect((await screen.findByRole("alert")).textContent).toBe(i18n.t("vendors.error.email_taken"));
  expect(i18n.exists("vendors.error.email_taken")).toBe(true);
});

test("validation and forbidden errors map to messages", async () => {
  mockApi("staff", [], json(422, { error: "validation", field: "email", code: "invalid" }));
  renderPage();
  fireEvent.change(await screen.findByLabelText(i18n.t("vendors.email")), { target: { value: "bad" } });
  fireEvent.click(screen.getByRole("button", { name: i18n.t("vendors.create") }));
  expect((await screen.findByRole("alert")).textContent).toBe(i18n.t("vendors.error.email.invalid"));
  cleanup();
  mockApi("staff", [], json(403, { error: "forbidden" }));
  renderPage();
  fireEvent.click(await screen.findByRole("button", { name: i18n.t("vendors.create") }));
  expect((await screen.findByRole("alert")).textContent).toBe(i18n.t("vendors.error.forbidden"));
});

test("only active, invited, disabled and expired rows offer actions", async () => {
  mockApi("staff", [v("p", "pending", true), v("r", "rejected", true), v("d", "disabled", true), v("x", "expired", true)]);
  renderPage();
  await screen.findByText("p@v.com");
  const row = (id: string) => screen.getByText(`${id}@v.com`).closest("tr")!;
  for (const id of ["p", "r"]) expect(within(row(id)).queryByRole("button")).toBeNull();
  expect(within(row("d")).getByRole("button", { name: i18n.t("vendors.enable") })).toBeTruthy();
  expect(within(row("d")).queryByRole("button", { name: i18n.t("vendors.disable") })).toBeNull();
  expect(within(row("d")).queryByRole("button", { name: i18n.t("vendors.changeExpiry") })).toBeNull();
  expect(within(row("x")).getByRole("button", { name: i18n.t("vendors.changeExpiry") })).toBeTruthy();
});

test("expiry editor shows the local day, not the UTC day", async () => {
  vi.spyOn(Date.prototype, "getTimezoneOffset").mockReturnValue(-480); // UTC+8
  const f = mockApi("staff", [{ ...v("m", "active", true), expires_at: "2026-11-07T20:00:00Z" }]);
  renderPage();
  await screen.findByText("m@v.com");
  fireEvent.click(screen.getByRole("button", { name: i18n.t("vendors.changeExpiry") }));
  const day = within(screen.getByText("m@v.com").closest("tr")!).getByLabelText(i18n.t("vendors.expiresOn")) as HTMLInputElement;
  expect(day.value).toBe("2026-11-08");
  fireEvent.click(screen.getByRole("button", { name: i18n.t("vendors.save") }));
  await waitFor(() => expect(find(f, "/api/vendors/m", "PATCH")).toBeTruthy());
  expect(JSON.parse(find(f, "/api/vendors/m", "PATCH")![1]!.body as string).expires_at).toMatch(/^2026-11-08T/);
  vi.restoreAllMocks();
});
