import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import i18n from "../i18n";
import Files from "./Files";

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status });
const file = (id: string, name: string, preview_status: string) => ({
  id, name, content_type: "application/pdf", size: 2048, sha256: "abcdef0123456789abcdef", created_at: "2030-01-01T00:00:00Z", preview_status, preview_kind: "pages", scan_status: "none", scan_result: null, request_id: null,
});

// routes by method + url; `list` answers GET /api/files in order (last one repeats)
function mockApi(list: Response[], del: () => Response = () => new Response(null, { status: 204 })) {
  let n = 0;
  const f = vi.fn(async (url: string, init?: RequestInit) => {
    if (url === "/api/files" && (init?.method ?? "GET") === "GET") return list[Math.min(n++, list.length - 1)].clone();
    if (init?.method === "DELETE") return del();
    if (url.endsWith("/preview")) return json(200, { kind: "pages", status: "ready", page_count: 1 });
    return json(404, { error: "not_found" });
  });
  vi.stubGlobal("fetch", f);
  return f;
}
const renderPage = () => render(<MemoryRouter><Files /></MemoryRouter>);

beforeEach(() => i18n.changeLanguage("en"));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); vi.useRealTimers(); });

test("empty list shows the empty message and settings link", async () => {
  mockApi([json(200, null)]);
  renderPage();
  expect(await screen.findByText("No files yet")).toBeTruthy();
  expect(screen.getByRole("link", { name: "Two-factor settings" }).getAttribute("href")).toBe("/settings/totp");
});

test("list failure shows the generic error", async () => {
  mockApi([json(500, { error: "boom" })]);
  renderPage();
  expect((await screen.findByRole("alert")).textContent).toBe("Something went wrong, please try again");
});

test("rows show size, short hash, preview status and actions", async () => {
  mockApi([json(200, [file("f1", "a.pdf", "ready"), file("f2", "b.pdf", "failed")])]);
  renderPage();
  expect(await screen.findByText("a.pdf")).toBeTruthy();
  expect(screen.getAllByText("2 KB")).toHaveLength(2);
  expect(screen.getAllByText("abcdef012345")).toHaveLength(2);
  expect(screen.getByText("Ready")).toBeTruthy();
  expect(screen.getByText("Preview failed")).toBeTruthy();
  // only the ready file gets a View button
  expect(screen.getAllByRole("button", { name: "View" })).toHaveLength(1);
  expect(screen.getAllByRole("link", { name: "Download" })[1].getAttribute("href")).toBe("/api/files/f2/content");
});

test("selecting files opens the share dialog with a not-ready hint", async () => {
  mockApi([json(200, [file("f1", "a.pdf", "ready"), file("f2", "b.pdf", "failed")])]);
  renderPage();
  const cb = await screen.findByLabelText("b.pdf");
  expect(screen.queryByRole("button", { name: /Create share/ })).toBeNull();
  fireEvent.click(cb);
  fireEvent.click(screen.getByLabelText("a.pdf"));
  fireEvent.click(screen.getByRole("button", { name: "Create share (2 selected)" }));
  const dlg = await screen.findByRole("dialog", { name: "Create share" });
  expect(dlg.textContent).toContain("Some selected files are not ready for preview");
  fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
  expect(screen.queryByRole("dialog")).toBeNull();
  // unticking deselects
  fireEvent.click(cb);
  fireEvent.click(screen.getByLabelText("a.pdf"));
  expect(screen.queryByRole("button", { name: /Create share/ })).toBeNull();
});

test("View opens the viewer on the file preview, Close dismisses it", async () => {
  const f = mockApi([json(200, [file("f1", "a.pdf", "ready")])]);
  renderPage();
  fireEvent.click(await screen.findByRole("button", { name: "View" }));
  expect(await screen.findByRole("dialog", { name: "File viewer" })).toBeTruthy();
  expect(f).toHaveBeenCalledWith("/api/files/f1/preview", expect.anything());
  fireEvent.click(screen.getByRole("button", { name: "Close" }));
  expect(screen.queryByRole("dialog")).toBeNull();
});

test("delete asks for confirmation, deletes and refreshes", async () => {
  const f = mockApi([json(200, [file("f1", "a.pdf", "ready")]), json(200, [])]);
  const confirm = vi.fn(() => false);
  vi.stubGlobal("confirm", confirm);
  renderPage();
  fireEvent.click(await screen.findByRole("button", { name: "Delete" }));
  expect(confirm).toHaveBeenCalledWith('Delete "a.pdf"?');
  expect(f.mock.calls.some(([, i]) => i?.method === "DELETE")).toBe(false);
  confirm.mockReturnValue(true);
  fireEvent.click(screen.getByRole("button", { name: "Delete" }));
  expect(await screen.findByText("No files yet")).toBeTruthy();
  expect(f).toHaveBeenCalledWith("/api/files/f1", expect.objectContaining({ method: "DELETE" }));
});

test("delete failure shows the generic error", async () => {
  mockApi([json(200, [file("f1", "a.pdf", "ready")])], () => json(500, {}));
  vi.stubGlobal("confirm", () => true);
  renderPage();
  fireEvent.click(await screen.findByRole("button", { name: "Delete" }));
  expect((await screen.findByRole("alert")).textContent).toBe("Something went wrong, please try again");
  expect(screen.getByText("a.pdf")).toBeTruthy();
});

test("pending previews are polled every 5s until ready", async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  const f = mockApi([json(200, [file("f1", "a.pdf", "pending")]), json(200, [file("f1", "a.pdf", "ready")])]);
  renderPage();
  expect(await screen.findByText("Processing")).toBeTruthy();
  await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
  await waitFor(() => expect(screen.getByText("Ready")).toBeTruthy());
  const lists = () => f.mock.calls.filter(([u]) => u === "/api/files").length;
  expect(lists()).toBe(2);
  await act(async () => { await vi.advanceTimersByTimeAsync(10000); });
  expect(lists()).toBe(2);
});

const scanned = (id: string, name: string, scan_status: string, scan_result: string | null = null) =>
  ({ ...file(id, name, "ready"), scan_status, scan_result, request_id: "rq1" });

test("quarantined file has no download or share", async () => {
  mockApi([json(200, [scanned("f1", "bad.pdf", "infected", "Eicar"), scanned("f2", "ok.pdf", "clean")])]);
  renderPage();
  expect(await screen.findByText("Infected (Eicar)")).toBeTruthy();
  expect(screen.getByText("Clean")).toBeTruthy();
  expect((screen.getByLabelText("bad.pdf") as HTMLInputElement).disabled).toBe(true);
  expect((screen.getByLabelText("ok.pdf") as HTMLInputElement).disabled).toBe(false);
  // only the clean file keeps a download link and an enabled View button
  expect(screen.getAllByRole("link", { name: "Download" })).toHaveLength(1);
  const views = screen.getAllByRole("button", { name: "View" }) as HTMLButtonElement[];
  expect(views.map((b) => b.disabled)).toEqual([true, false]);
});

test("pending scan polls", async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  const pendingScan = { ...scanned("f1", "a.pdf", "pending") };
  const f = mockApi([json(200, [pendingScan]), json(200, [scanned("f1", "a.pdf", "clean")])]);
  renderPage();
  expect(await screen.findByText("Scanning")).toBeTruthy();
  await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
  await waitFor(() => expect(screen.getByText("Clean")).toBeTruthy());
  expect(f.mock.calls.filter(([u]) => u === "/api/files").length).toBe(2);
});

test("staff uploads show no scan badge", async () => {
  mockApi([json(200, [file("f1", "a.pdf", "ready")])]);
  renderPage();
  await screen.findByText("a.pdf");
  expect(screen.queryByText("Clean")).toBeNull();
});
