import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import i18n from "../../i18n";
import { nav } from "../../api";
import VendorShare from "./VendorShare";

const body = (extra = {}) => ({
  message: "hi", expires_at: "2030-01-01T00:00:00Z", allow_download: true, watermark: false,
  files: [{ id: "f1", name: "a.pdf", size: 2048, available: true, ...extra }],
});
const json = (status: number, b: unknown) => new Response(JSON.stringify(b), { status });
const show = () => render(<MemoryRouter initialEntries={["/vendor/shares/s1"]}><Routes><Route path="/vendor/shares/:id" element={<VendorShare />} /></Routes></MemoryRouter>);

beforeEach(() => i18n.changeLanguage("en"));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

test("download link and viewer use the vendor paths", async () => {
  const f = vi.fn(async (url: string) => (url.endsWith("/preview") ? json(200, { kind: "none", status: "failed", page_count: 0 }) : json(200, body())));
  vi.stubGlobal("fetch", f);
  const go = vi.spyOn(nav, "go").mockImplementation(() => {});
  show();
  const link = (await screen.findByRole("link", { name: "Download" })) as HTMLAnchorElement;
  expect(link.getAttribute("href")).toBe("/api/vendor/shares/s1/files/f1/content");
  fireEvent.click(link);
  await waitFor(() => expect(go).toHaveBeenCalledWith("/api/vendor/shares/s1/files/f1/content"));
  fireEvent.click(screen.getByRole("button", { name: "View" }));
  await waitFor(() => expect(f).toHaveBeenCalledWith("/api/vendor/shares/s1/files/f1/preview", expect.anything()));
});

test("mark_pending shows the note instead of downloading", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => json(200, body({ mark_pending: true }))));
  const go = vi.spyOn(nav, "go").mockImplementation(() => {});
  show();
  fireEvent.click(await screen.findByRole("link", { name: "Download" }));
  expect(await screen.findByRole("alert")).toBeTruthy();
  expect(go).not.toHaveBeenCalled();
});

test("410 shows the expired message", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => json(410, { error: "gone" })));
  show();
  expect(await screen.findByText("This share has expired or been revoked")).toBeTruthy();
});

test("401 sends the vendor to the login page", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => json(401, { error: "unauthorized" })));
  render(<MemoryRouter initialEntries={["/vendor/shares/s1"]}><Routes><Route path="/vendor/shares/:id" element={<VendorShare />} /><Route path="/login" element={<p>login page</p>} /></Routes></MemoryRouter>);
  expect(await screen.findByText("login page")).toBeTruthy();
});
