import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import i18n from "../i18n";
import RequestDetail from "./RequestDetail";

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status });
const detail = (revoked = false) => ({
  id: "r1", created_at: "2030-01-01T00:00:00Z", expires_at: "2030-01-08T00:00:00Z", revoked, expired: false,
  file_count: 2, total_bytes: 30, max_files: 10, max_total_bytes: 1024 ** 3, uploader_count: 1,
  url: "https://sx.example/r/tok123", message: "hi", allowed_exts: ["pdf"],
  uploaders: [{ id: "u1", email: "up@x.com", first_opened_at: null, last_access_at: "2030-01-02T00:00:00Z" }],
  files: [
    { id: "f1", name: "bad.pdf", size: 10, uploader_email: "up@x.com", created_at: "2030-01-02T00:00:00Z", scan_status: "infected", scan_result: "Win.Test.EICAR_HDB-1", deleted: false },
    { id: "f2", name: "ok.pdf", size: 20, uploader_email: "up@x.com", created_at: "2030-01-02T00:00:00Z", scan_status: "clean", scan_result: null, deleted: true },
  ],
});
const renderPage = () =>
  render(<MemoryRouter initialEntries={["/requests/r1"]}><Routes><Route path="/requests/:id" element={<RequestDetail />} /></Routes></MemoryRouter>);

beforeEach(() => i18n.changeLanguage("en"));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

test("shows infected badge with signature", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => json(200, detail())));
  renderPage();
  expect(await screen.findByText(`${i18n.t("scan.infected")} (Win.Test.EICAR_HDB-1)`)).toBeTruthy();
  expect(screen.getByText(i18n.t("scan.clean"))).toBeTruthy();
  expect(screen.getByText("https://sx.example/r/tok123")).toBeTruthy();
  expect(screen.getAllByText("up@x.com", { selector: "td" })).toHaveLength(3);
});

test("copy button copies the link", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => json(200, detail())));
  const writeText = vi.fn(async () => {});
  vi.stubGlobal("navigator", { ...navigator, clipboard: { writeText } });
  renderPage();
  fireEvent.click(await screen.findByRole("button", { name: i18n.t("requests.copy") }));
  expect(writeText).toHaveBeenCalledWith("https://sx.example/r/tok123");
});

test("revoke asks for confirmation", async () => {
  let revoked = false;
  const f = vi.fn(async (_u: string, init?: RequestInit) => {
    if (init?.method === "POST") { revoked = true; return new Response(null, { status: 204 }); }
    return json(200, detail(revoked));
  });
  vi.stubGlobal("fetch", f);
  const confirm = vi.fn(() => false);
  vi.stubGlobal("confirm", confirm);
  renderPage();
  const btn = await screen.findByRole("button", { name: i18n.t("requests.revoke") });
  fireEvent.click(btn);
  expect(confirm).toHaveBeenCalledWith(i18n.t("requests.confirmRevoke"));
  expect(f.mock.calls.some(([, i]) => i?.method === "POST")).toBe(false);
  confirm.mockReturnValue(true);
  fireEvent.click(btn);
  await waitFor(() => expect(screen.queryByRole("button", { name: i18n.t("requests.revoke") })).toBeNull());
  expect(f).toHaveBeenCalledWith("/api/requests/r1/revoke", expect.objectContaining({ method: "POST" }));
});

test("load failure shows the generic error", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => json(404, { error: "not_found" })));
  renderPage();
  expect((await screen.findByRole("alert")).textContent).toBe(i18n.t("app.error"));
});
