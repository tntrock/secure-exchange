import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import i18n from "../../i18n";
import Users from "./Users";

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status });
const u = (o: object) => ({ id: "u1", email: "a@x.com", display_name: "Ann", role: "staff", auth_source: "local", status: "active", totp_enabled: true, last_login_at: "2026-11-01T10:00:00Z", created_at: "2026-10-01T10:00:00Z", ...o });
const ROWS = [
  u({}),
  u({ id: "u2", email: "inv@x.com", display_name: "Inv", status: "invited", totp_enabled: false, last_login_at: null }),
  u({ id: "u3", email: "ext@x.com", display_name: "Ext", auth_source: "oidc" }),
  u({ id: "u4", email: "v@x.com", display_name: "Ven", role: "vendor", status: "pending" }),
];
function setup(rows: object[] = ROWS, post: () => Response = () => new Response(null, { status: 204 })) {
  const f = vi.fn(async (_url: string, init?: RequestInit) => {
    if (!init?.method || init.method === "GET") return json(200, rows);
    return post();
  });
  vi.stubGlobal("fetch", f);
  render(<Users />);
  return f;
}
const rowOf = (email: string) => screen.getByText(email).closest("tr")!;

beforeEach(() => i18n.changeLanguage("en"));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

test("table shows the columns and rows", async () => {
  setup();
  await screen.findByText("a@x.com");
  for (const h of ["Email", "Display name", "Role", "Source", "Status", "TOTP", "Last login"]) expect(screen.getByRole("columnheader", { name: h })).toBeTruthy();
  expect(within(rowOf("inv@x.com")).getByText("Invited")).toBeTruthy();
});

test("create form posts and the new row appears", async () => {
  let rows = [...ROWS];
  const f = vi.fn(async (_u: string, init?: RequestInit) => {
    if (init?.method === "POST") { rows = [...rows, u({ id: "u9", email: "new@x.com", display_name: "New" })]; return json(201, rows[rows.length - 1]); }
    return json(200, rows);
  });
  vi.stubGlobal("fetch", f);
  render(<Users />);
  await screen.findByText("a@x.com");
  fireEvent.change(screen.getByLabelText("Email"), { target: { value: "new@x.com" } });
  fireEvent.change(screen.getByLabelText("Display name"), { target: { value: "New" } });
  fireEvent.change(screen.getByLabelText("Role"), { target: { value: "admin" } });
  fireEvent.click(screen.getByRole("button", { name: "Create and invite" }));
  expect(await screen.findByText("new@x.com")).toBeTruthy();
  expect(f).toHaveBeenCalledWith("/api/admin/users", expect.objectContaining({ method: "POST", body: JSON.stringify({ email: "new@x.com", display_name: "New", role: "admin" }) }));
});

test("reset TOTP asks for confirmation", async () => {
  const f = setup();
  await screen.findByText("a@x.com");
  const conf = vi.spyOn(window, "confirm").mockReturnValueOnce(false).mockReturnValueOnce(true);
  fireEvent.click(within(rowOf("a@x.com")).getByRole("button", { name: "Reset TOTP" }));
  expect(f.mock.calls.filter((c) => c[1]?.method === "POST")).toHaveLength(0);
  fireEvent.click(within(rowOf("a@x.com")).getByRole("button", { name: "Reset TOTP" }));
  await waitFor(() => expect(f).toHaveBeenCalledWith("/api/admin/users/u1/reset-totp", expect.objectContaining({ method: "POST" })));
  expect(conf).toHaveBeenCalledTimes(2);
});

test("role select only for local non-vendor rows; change patches", async () => {
  const f = setup();
  await screen.findByText("a@x.com");
  expect(within(rowOf("a@x.com")).getByRole("combobox")).toBeTruthy();
  expect(within(rowOf("ext@x.com")).queryByRole("combobox")).toBeNull();
  expect(within(rowOf("v@x.com")).queryByRole("combobox")).toBeNull();
  fireEvent.change(within(rowOf("a@x.com")).getByRole("combobox"), { target: { value: "admin" } });
  await waitFor(() => expect(f).toHaveBeenCalledWith("/api/admin/users/u1", expect.objectContaining({ method: "PATCH", body: JSON.stringify({ role: "admin" }) })));
});

test("reinvite only when invited; disable and enable by status", async () => {
  const f = setup([...ROWS, u({ id: "u5", email: "dis@x.com", status: "disabled" })]);
  await screen.findByText("a@x.com");
  expect(within(rowOf("inv@x.com")).getByRole("button", { name: "Reinvite" })).toBeTruthy();
  expect(within(rowOf("a@x.com")).queryByRole("button", { name: "Reinvite" })).toBeNull();
  expect(within(rowOf("dis@x.com")).getByRole("button", { name: "Enable" })).toBeTruthy();
  fireEvent.click(within(rowOf("a@x.com")).getByRole("button", { name: "Disable" }));
  await waitFor(() => expect(f).toHaveBeenCalledWith("/api/admin/users/u1/disable", expect.objectContaining({ method: "POST" })));
});

test.each([
  ["last_admin", "Cannot disable or demote the last local administrator"],
  ["external_account", "Accounts from an external login source cannot be changed here"],
  ["email_taken", "This email address is already in use"],
  ["wrong_state", "That action is not allowed in the account's current state"],
])("409 %s shows its message", async (code, msg) => {
  setup(ROWS, () => json(409, { error: code }));
  await screen.findByText("a@x.com");
  fireEvent.click(within(rowOf("a@x.com")).getByRole("button", { name: "Disable" }));
  expect((await screen.findByRole("alert")).textContent).toBe(msg);
});

test("422 on create shows generic error; list failure shows app error", async () => {
  setup(ROWS, () => json(422, { error: "validation", field: "email", code: "invalid" }));
  await screen.findByText("a@x.com");
  fireEvent.change(screen.getByLabelText("Email"), { target: { value: "x" } });
  fireEvent.click(screen.getByRole("button", { name: "Create and invite" }));
  expect((await screen.findByRole("alert")).textContent).toBe("Something went wrong, please check the form");
  cleanup();
  vi.stubGlobal("fetch", vi.fn(async () => json(500, {})));
  render(<Users />);
  expect((await screen.findByRole("alert")).textContent).toBe("Something went wrong, please try again");
});

test("no Reinvite on an invited vendor row", async () => {
  setup([u({ id: "u7", email: "iv@x.com", role: "vendor", status: "invited" })]);
  await screen.findByText("iv@x.com");
  expect(within(rowOf("iv@x.com")).queryByRole("button", { name: "Reinvite" })).toBeNull();
});
