import { afterEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import i18n from "../i18n";
import ShareDialog from "./ShareDialog";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function setup(fetchImpl: () => Promise<Response>) {
  const f = vi.fn(fetchImpl);
  vi.stubGlobal("fetch", f);
  render(<MemoryRouter><ShareDialog fileIds={["f1"]} onClose={() => {}} /></MemoryRouter>);
  fireEvent.change(screen.getByLabelText(i18n.t("share.recipients")), { target: { value: "a@x.com, b@x.com\n" } });
  fireEvent.click(screen.getByRole("button", { name: i18n.t("share.submit") }));
  return f;
}

test("submits parsed recipients, ISO expiry and default flags", async () => {
  const f = setup(() => Promise.resolve(new Response(JSON.stringify({ id: "s1" }), { status: 201 })));
  await waitFor(() => expect(f).toHaveBeenCalled());
  const [url, init] = f.mock.calls[0] as unknown as [string, RequestInit];
  expect(url).toBe("/api/shares");
  const body = JSON.parse(init.body as string);
  expect(body.emails).toEqual(["a@x.com", "b@x.com"]);
  expect(body.file_ids).toEqual(["f1"]);
  expect(body.expires_at).toMatch(/^\d{4}-\d\d-\d\dT.*Z$/);
  expect(body.allow_download).toBe(false);
  expect(body.watermark).toBe(true);
  expect(body.max_views).toBeNull();
  expect(body.ip_allow).toEqual([]);
});

test("every form field reaches the request body", async () => {
  const f = vi.fn((_u: string, _i?: RequestInit) => Promise.resolve(new Response(JSON.stringify({ id: "s9" }), { status: 201 })));
  vi.stubGlobal("fetch", f);
  render(
    <MemoryRouter>
      <Routes>
        <Route path="/" element={<ShareDialog fileIds={["f1", "f2"]} onClose={() => {}} />} />
        <Route path="/shares/:id" element={<p>detail page</p>} />
      </Routes>
    </MemoryRouter>,
  );
  const field = (k: string) => screen.getByLabelText(i18n.t(k));
  fireEvent.change(field("share.recipients"), { target: { value: "a@x.com" } });
  fireEvent.click(field("share.allowDownload"));
  expect(screen.queryByText(i18n.t("share.viewOnlyNote"))).toBeNull();
  fireEvent.click(field("share.watermark"));
  fireEvent.change(field("share.expiresAt"), { target: { value: "2030-01-02T03:04" } });
  fireEvent.change(field("share.maxViews"), { target: { value: "7" } });
  fireEvent.change(field("share.ipAllow"), { target: { value: "10.0.0.1\n10.0.0.0/8" } });
  fireEvent.change(field("share.message"), { target: { value: "see attached" } });
  fireEvent.click(screen.getByRole("button", { name: i18n.t("share.submit") }));
  expect(await screen.findByText("detail page")).toBeTruthy();
  const body = JSON.parse(f.mock.calls[0][1]!.body as string);
  expect(body).toEqual({
    file_ids: ["f1", "f2"], emails: ["a@x.com"], allow_download: true, watermark: false,
    expires_at: new Date("2030-01-02T03:04").toISOString(), max_views: 7, ip_allow: ["10.0.0.1", "10.0.0.0/8"], message: "see attached",
  });
});

test("a cleared expiry is sent empty so the server reports it", async () => {
  const f = setupWith(() => fireEvent.change(screen.getByLabelText(i18n.t("share.expiresAt")), { target: { value: "" } }),
    () => Promise.resolve(new Response(JSON.stringify({ error: "validation", field: "expires_at", code: "required" }), { status: 422 })));
  expect(await screen.findByText(i18n.t("share.error.expires_at.required"))).toBeTruthy();
  expect(JSON.parse(f.mock.calls[0][1]!.body as string).expires_at).toBe("");
});

test("Cancel calls onClose; network failure shows the generic error", async () => {
  const onClose = vi.fn();
  vi.stubGlobal("fetch", vi.fn(() => Promise.reject(new TypeError("offline"))));
  render(<MemoryRouter><ShareDialog fileIds={["f1"]} onClose={onClose} /></MemoryRouter>);
  fireEvent.click(screen.getByRole("button", { name: i18n.t("share.cancel") }));
  expect(onClose).toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: i18n.t("share.submit") }));
  expect((await screen.findByRole("alert")).textContent).toBe(i18n.t("share.error.generic"));
  expect((screen.getByRole("button", { name: i18n.t("share.submit") }) as HTMLButtonElement).disabled).toBe(false);
});

function setupWith(edit: () => void, fetchImpl: () => Promise<Response>) {
  const f = vi.fn((_u: string, _i?: RequestInit) => fetchImpl());
  vi.stubGlobal("fetch", f);
  render(<MemoryRouter><ShareDialog fileIds={["f1"]} onClose={() => {}} /></MemoryRouter>);
  edit();
  fireEvent.click(screen.getByRole("button", { name: i18n.t("share.submit") }));
  return f;
}

test("422 shows the field error text", async () => {
  setup(() => Promise.resolve(new Response(JSON.stringify({ error: "validation", field: "emails", code: "invalid" }), { status: 422 })));
  expect(await screen.findByText(i18n.t("share.error.emails.invalid"))).toBeTruthy();
});

test("unknown 422 combination falls back to generic", async () => {
  setup(() => Promise.resolve(new Response(JSON.stringify({ error: "validation", field: "emails", code: "weird" }), { status: 422 })));
  expect(await screen.findByText(i18n.t("share.error.generic"))).toBeTruthy();
});

test.each(["preview_pending", "not_previewable"])("422 file_ids.%s shows its message", async (code) => {
  setup(() => Promise.resolve(new Response(JSON.stringify({ error: "validation", field: "file_ids", code }), { status: 422 })));
  expect(await screen.findByText(i18n.t(`share.error.file_ids.${code}`))).toBeTruthy();
});

test("view-only with a non-ready file shows the hint before submit", () => {
  vi.stubGlobal("fetch", vi.fn());
  render(<MemoryRouter><ShareDialog fileIds={["f1"]} notReady onClose={() => {}} /></MemoryRouter>);
  expect(screen.getByText(i18n.t("share.previewHint"))).toBeTruthy();
});

// ---- trace marks ----
import type { FileInfo } from "../api";
const mk = (name: string, watermark: string, plain: string, degraded: boolean, id = name): FileInfo => ({
  id, name, content_type: "", size: 1, sha256: "", created_at: "", preview_status: "ready", preview_kind: "", mark: { watermark, plain, degraded },
} as FileInfo);
const renderWith = (files: FileInfo[]) => {
  render(<MemoryRouter><ShareDialog fileIds={files.map((f) => f.id)} files={files} onClose={() => {}} /></MemoryRouter>);
};
const allow = () => fireEvent.click(screen.getByLabelText(i18n.t("share.allowDownload")));

test("degraded file with download+watermark warns and names the file; off without download", () => {
  renderWith([mk("a.zip", "none", "none", true)]);
  expect(screen.queryByText(/a\.zip/)).toBeNull();
  allow();
  expect(screen.getByText(i18n.t("share.markDegraded"))).toBeTruthy();
  expect(screen.getByText("a.zip")).toBeTruthy();
  fireEvent.click(screen.getByLabelText(i18n.t("share.watermark")));
  expect(screen.queryByText(i18n.t("share.markDegraded"))).toBeNull();
  expect(screen.getByText(i18n.t("share.markNone"))).toBeTruthy();
  allow();
  expect(screen.queryByText(i18n.t("share.markNone"))).toBeNull();
});

test("office file with watermark says it is delivered as PDF", () => {
  renderWith([mk("r.docx", "pdf_pages", "ooxml_meta", false), mk("p.pdf", "pdf_pages", "pdf_meta", false)]);
  allow();
  expect(screen.getByText(i18n.t("share.officeAsPdf"))).toBeTruthy();
  expect(screen.getByText("r.docx")).toBeTruthy();
  expect(screen.queryByText("p.pdf")).toBeNull();
});

test("422 unmarkable shows markBlocked with the file names", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ error: "unmarkable", file_ids: ["b"] }), { status: 422 })));
  renderWith([mk("a.pdf", "pdf_pages", "pdf_meta", false, "a"), mk("b.zip", "none", "none", true, "b")]);
  fireEvent.change(screen.getByLabelText(i18n.t("share.recipients")), { target: { value: "a@x.com" } });
  fireEvent.click(screen.getByRole("button", { name: i18n.t("share.submit") }));
  expect((await screen.findByRole("alert")).textContent).toContain(i18n.t("share.markBlocked"));
  expect(screen.getAllByText("b.zip").length).toBeGreaterThan(0);
});

test("a name merely ending in 'docx' without a dot is not an Office file", () => {
  renderWith([mk("notdocx", "pdf_pages", "none", false)]);
  allow();
  expect(screen.queryByText(i18n.t("share.officeAsPdf"))).toBeNull();
});
