import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import i18n from "../i18n";
import Settings from "./Settings";

beforeEach(() => i18n.changeLanguage("en"));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

test("loads prefs, saves with PUT, shows fixed note and totp link", async () => {
  const f = vi.fn(async (_u: string, init?: RequestInit) =>
    init?.method === "PUT" ? new Response(null, { status: 204 }) : new Response(JSON.stringify({ first_open: true, download: false, upload: true })));
  vi.stubGlobal("fetch", f);
  render(<MemoryRouter><Settings /></MemoryRouter>);
  const dl = (await screen.findByLabelText(i18n.t("settings.download"))) as HTMLInputElement;
  expect(dl.checked).toBe(false);
  expect((screen.getByLabelText(i18n.t("settings.first_open")) as HTMLInputElement).checked).toBe(true);
  expect(screen.getByText(i18n.t("settings.virusNote"))).toBeTruthy();
  expect(screen.getByRole("link", { name: i18n.t("settings.totp") }).getAttribute("href")).toBe("/settings/totp");
  fireEvent.click(dl);
  fireEvent.click(screen.getByRole("button", { name: i18n.t("settings.save") }));
  await waitFor(() => expect(f).toHaveBeenCalledWith("/api/me/notifications", expect.objectContaining({ method: "PUT", body: JSON.stringify({ first_open: true, download: true, upload: true }) })));
  expect(await screen.findByText(i18n.t("settings.saved"))).toBeTruthy();
});

test("load error shows an alert", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 500 })));
  render(<MemoryRouter><Settings /></MemoryRouter>);
  expect(await screen.findByRole("alert")).toBeTruthy();
});

test("save failure shows an alert", async () => {
  vi.stubGlobal("fetch", vi.fn(async (_u: string, init?: RequestInit) =>
    init?.method === "PUT" ? new Response("{}", { status: 500 }) : new Response(JSON.stringify({ first_open: true, download: true, upload: true }))));
  render(<MemoryRouter><Settings /></MemoryRouter>);
  await screen.findByLabelText(i18n.t("settings.download"));
  fireEvent.click(screen.getByRole("button", { name: i18n.t("settings.save") }));
  expect(await screen.findByRole("alert")).toBeTruthy();
});

test.each([["ldap", false], ["local", true]])("totp link for auth_source %s shown=%s", async (src, shown) => {
  vi.stubGlobal("fetch", vi.fn(async (url: string) =>
    new Response(JSON.stringify(url === "/api/me" ? { id: "u", role: "staff", auth_source: src } : { first_open: true, download: true, upload: true }))));
  render(<MemoryRouter><Settings /></MemoryRouter>);
  await screen.findByLabelText(i18n.t("settings.download"));
  await act(async () => {});
  expect(!!screen.queryByRole("link", { name: i18n.t("settings.totp") })).toBe(shown);
});
