import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import i18n from "../../i18n";
import VendorShares from "./VendorShares";

beforeEach(() => i18n.changeLanguage("en"));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

test("lists shares with owner, message, count and a link", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify([
    { id: "s1", owner_name: "Alice", message: "Q3 docs", expires_at: "2030-01-01T00:00:00Z", file_count: 3, allow_download: true, watermark: false },
  ]))));
  render(<MemoryRouter><VendorShares /></MemoryRouter>);
  expect(await screen.findByText("Alice")).toBeTruthy();
  expect(screen.getByText("Q3 docs")).toBeTruthy();
  expect(screen.getByText("3")).toBeTruthy();
  expect(screen.getByRole("link", { name: "Open" }).getAttribute("href")).toBe("/vendor/shares/s1");
});

test("empty list says so", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => new Response("[]")));
  render(<MemoryRouter><VendorShares /></MemoryRouter>);
  expect(await screen.findByText("Nothing has been shared with you yet")).toBeTruthy();
});

test.each([["domain_blocked", "recipient.error.domain_blocked"], ["ip_denied", "recipient.error.ipDenied"]])("403 %s shows its own message", async (error, key) => {
  vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ error }), { status: 403 })));
  render(<MemoryRouter><VendorShares /></MemoryRouter>);
  expect(await screen.findByText(i18n.t(key))).toBeTruthy();
});

test("401 sends the vendor to the login page with the return path", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ error: "unauthorized" }), { status: 401 })));
  const Stub = () => <p>login from {String((useLocation().state as { from?: string } | null)?.from)}</p>;
  render(<MemoryRouter initialEntries={["/vendor/shares?q=1"]}><Routes><Route path="/vendor/shares" element={<VendorShares />} /><Route path="/login" element={<Stub />} /></Routes></MemoryRouter>);
  expect(await screen.findByText("login from /vendor/shares?q=1")).toBeTruthy();
});
