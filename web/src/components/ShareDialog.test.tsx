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
  const f = vi.fn((_u: string, _i?: RequestInit) => fetchImpl());
  vi.stubGlobal("fetch", f);
  render(<MemoryRouter><ShareDialog fileIds={["f1"]} onClose={() => {}} /></MemoryRouter>);
  fireEvent.change(screen.getByLabelText(i18n.t("share.recipients")), { target: { value: "a@x.com, b@x.com\n" } });
  fireEvent.click(screen.getByRole("button", { name: i18n.t("share.submit") }));
  return f;
}

test("submits parsed recipients, ISO expiry and default flags", async () => {
  const f = setup(() => Promise.resolve(new Response(JSON.stringify({ id: "s1" }), { status: 201 })));
  await waitFor(() => expect(f.mock.calls.some((c) => c[0] === "/api/shares")).toBe(true));
  const [url, init] = f.mock.calls.find((c) => c[0] === "/api/shares") as unknown as [string, RequestInit];
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
  const body = JSON.parse(f.mock.calls.find((c) => c[0] === "/api/shares")![1]!.body as string);
  expect(body).toEqual({
    file_ids: ["f1", "f2"], emails: ["a@x.com"], vendor_ids: [], allow_download: true, watermark: false,
    expires_at: new Date("2030-01-02T03:04").toISOString(), max_views: 7, ip_allow: ["10.0.0.1", "10.0.0.0/8"], message: "see attached",
  });
});

test("a cleared expiry is sent empty so the server reports it", async () => {
  const f = setupWith(() => fireEvent.change(screen.getByLabelText(i18n.t("share.expiresAt")), { target: { value: "" } }),
    () => Promise.resolve(new Response(JSON.stringify({ error: "validation", field: "expires_at", code: "required" }), { status: 422 })));
  expect(await screen.findByText(i18n.t("share.error.expires_at.required"))).toBeTruthy();
  expect(JSON.parse(f.mock.calls.find((c) => c[0] === "/api/shares")![1]!.body as string).expires_at).toBe("");
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

const vendorRows = [
  { id: "v1", email: "al@v.com", display_name: "Al", org: "Acme", status: "active", expires_at: "2030-01-01T00:00:00Z", created_by_name: "S", created_at: "2029-01-01T00:00:00Z", can_manage: false },
  { id: "v2", email: "bo@g.com", display_name: "Bo", org: "Globex", status: "active", expires_at: "2030-01-01T00:00:00Z", created_by_name: "S", created_at: "2029-01-01T00:00:00Z", can_manage: false },
];
function vendorSetup() {
  const f = vi.fn(async (url: string, init?: RequestInit) =>
    url.startsWith("/api/vendors") ? new Response(JSON.stringify(vendorRows)) : new Response(JSON.stringify({ id: "s1" }), { status: init?.method === "POST" ? 201 : 200 }));
  vi.stubGlobal("fetch", f);
  render(<MemoryRouter><ShareDialog fileIds={["f1"]} onClose={() => {}} /></MemoryRouter>);
  return f;
}

test("can share to vendors only", async () => {
  const f = vendorSetup();
  fireEvent.click(await screen.findByRole("checkbox", { name: /Al <al@v.com> · Acme/ }));
  fireEvent.click(screen.getByRole("button", { name: i18n.t("share.submit") }));
  await waitFor(() => expect(f.mock.calls.some((c) => c[0] === "/api/shares")).toBe(true));
  const call = f.mock.calls.find((c) => c[0] === "/api/shares") as unknown as [string, RequestInit];
  const body = JSON.parse(call[1].body as string);
  expect(body.vendor_ids).toEqual(["v1"]);
  expect(body.emails).toEqual([]);
  expect(f.mock.calls.some((c) => c[0] === "/api/vendors?active=1")).toBe(true);
});

test("filters vendor list", async () => {
  vendorSetup();
  await screen.findByRole("checkbox", { name: /Bo/ });
  fireEvent.change(screen.getByLabelText(i18n.t("vendors.filter")), { target: { value: "globex" } });
  expect(screen.queryByRole("checkbox", { name: /al@v.com/ })).toBeNull();
  expect(screen.getByRole("checkbox", { name: /Bo/ })).toBeTruthy();
});

test("recipients/required and vendor_ids/not_found have messages", () => {
  expect(i18n.exists("share.error.recipients.required")).toBe(true);
  expect(i18n.exists("share.error.vendor_ids.not_found")).toBe(true);
});

const rulesBody = { force_watermark: false, forbid_download: false, share_default_days: 7 };
function setupRules(rules: object, shareRes?: () => Response) {
  const f = vi.fn(async (u: string, _i?: RequestInit) => (u === "/api/rules" ? new Response(JSON.stringify({ ...rulesBody, ...rules })) : shareRes?.() ?? new Response("[]")));
  vi.stubGlobal("fetch", f);
  render(<MemoryRouter><ShareDialog fileIds={["f1"]} onClose={() => {}} /></MemoryRouter>);
  return f;
}

test("forbid_download locks the download checkbox off", async () => {
  setupRules({ forbid_download: true });
  const cb = screen.getByLabelText(i18n.t("share.allowDownload")) as HTMLInputElement;
  await waitFor(() => expect(cb.disabled).toBe(true));
  expect(cb.checked).toBe(false);
  expect(screen.getAllByText(i18n.t("share.lockedByAdmin"))).toHaveLength(1);
});

test("force_watermark locks the watermark checkbox on", async () => {
  setupRules({ force_watermark: true });
  const cb = screen.getByLabelText(i18n.t("share.watermark")) as HTMLInputElement;
  await waitFor(() => expect(cb.disabled).toBe(true));
  expect(cb.checked).toBe(true);
  expect(screen.getAllByText(i18n.t("share.lockedByAdmin"))).toHaveLength(1);
});

test("default expiry follows share_default_days", async () => {
  setupRules({ share_default_days: 3 });
  const el = screen.getByLabelText(i18n.t("share.expiresAt")) as HTMLInputElement;
  const want = (d: number) => { const x = new Date(Date.now() + d * 864e5); x.setMinutes(x.getMinutes() - x.getTimezoneOffset()); return x.toISOString().slice(0, 13); };
  await waitFor(() => expect(el.value.slice(0, 13)).toBe(want(3)));
});

test("emails/domain_blocked renders its message", async () => {
  setupRules({}, () => new Response(JSON.stringify({ error: "validation", field: "emails", code: "domain_blocked" }), { status: 422 }));
  fireEvent.change(screen.getByLabelText(i18n.t("share.recipients")), { target: { value: "a@bad.com" } });
  fireEvent.click(screen.getByRole("button", { name: i18n.t("share.submit") }));
  expect(await screen.findByText(i18n.t("share.error.emails.domain_blocked"))).toBeTruthy();
});

test("expiry input max follows share_max_days", async () => {
  setupRules({ share_max_days: 10 });
  const el = screen.getByLabelText(i18n.t("share.expiresAt")) as HTMLInputElement;
  const want = (d: number) => { const x = new Date(Date.now() + d * 864e5); x.setMinutes(x.getMinutes() - x.getTimezoneOffset()); return x.toISOString().slice(0, 13); };
  await waitFor(() => expect(el.max.slice(0, 13)).toBe(want(10)));
});
