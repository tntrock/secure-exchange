import { afterEach, expect, test, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import i18n from "../i18n";
import Shell from "./Shell";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
const show = (role: string, version?: string) => render(<MemoryRouter><Shell role={role} version={version}>x</Shell></MemoryRouter>);

test("trace link only for admins", () => {
  show("admin");
  expect(screen.getByRole("link", { name: i18n.t("nav.trace") })).toBeTruthy();
  cleanup();
  show("user");
  expect(screen.queryByRole("link", { name: i18n.t("nav.trace") })).toBeNull();
});

test("logout calls the API", () => {
  const f = vi.fn(async () => new Response(null, { status: 204 }));
  vi.stubGlobal("fetch", f);
  show("user");
  screen.getByRole("button", { name: i18n.t("app.logout") }).click();
  expect(f).toHaveBeenCalledWith("/api/auth/logout", expect.anything());
});

test("requests link for everyone", () => {
  show("user");
  expect(screen.getByRole("link", { name: i18n.t("nav.requests") }).getAttribute("href")).toBe("/requests");
});

test("vendors link for staff and admin", () => {
  show("user");
  expect(screen.getByRole("link", { name: i18n.t("nav.vendors") }).getAttribute("href")).toBe("/vendors");
});

test("vendor nav is shared-with-me and upload only", () => {
  show("vendor");
  expect(screen.getByRole("link", { name: i18n.t("nav.sharedWithMe") }).getAttribute("href")).toBe("/vendor/shares");
  expect(screen.getByRole("link", { name: i18n.t("nav.vendorUpload") }).getAttribute("href")).toBe("/vendor/upload");
  for (const k of ["files", "shares", "requests", "vendors"]) expect(screen.queryByRole("link", { name: i18n.t(`nav.${k}`) })).toBeNull();
});

const fwd = (alert: boolean) => {
  const f = vi.fn(async (u: string) => new Response(JSON.stringify(u.includes("forwarding") ? { enabled: true, pending: 1, last_ok_at: null, failing_since: null, last_error: "", alert } : {})));
  vi.stubGlobal("fetch", f);
  return f;
};

test("admin sees the forwarding alert only when alert is true", async () => {
  fwd(true);
  show("admin");
  expect(await screen.findByText(i18n.t("audit.fwdAlert"))).toBeTruthy();
  cleanup();
  const f = fwd(false);
  show("admin");
  await waitFor(() => expect(f).toHaveBeenCalledWith("/api/admin/audit/forwarding", expect.anything()));
  expect(screen.queryByText(i18n.t("audit.fwdAlert"))).toBeNull();
});

test("forwarding failures are ignored; staff never fetch it", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("down"); }));
  show("admin");
  expect(screen.getByRole("link", { name: i18n.t("nav.audit") }).getAttribute("href")).toBe("/admin/audit");
  cleanup();
  const f = fwd(true);
  show("user");
  expect(screen.queryByRole("link", { name: i18n.t("nav.audit") })).toBeNull();
  expect(screen.getByRole("link", { name: i18n.t("nav.settings") }).getAttribute("href")).toBe("/settings");
  expect(f).not.toHaveBeenCalled();
});

test("vendors have no settings link", () => {
  show("vendor");
  expect(screen.queryByRole("link", { name: i18n.t("nav.settings") })).toBeNull();
});

test("version footer only for admins", () => {
  vi.stubGlobal("fetch", vi.fn(async () => new Response("{}")));
  show("admin", "9.9.9");
  expect(screen.getByText("v9.9.9")).toBeTruthy();
  cleanup();
  show("user", "9.9.9");
  expect(screen.queryByText("v9.9.9")).toBeNull();
});
