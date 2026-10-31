import { afterEach, expect, test, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import i18n from "../i18n";
import Shell from "./Shell";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
const show = (role: string) => render(<MemoryRouter><Shell role={role}>x</Shell></MemoryRouter>);

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
