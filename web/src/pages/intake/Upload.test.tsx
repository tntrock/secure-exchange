import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";

const { ctor, uploads } = vi.hoisted(() => ({
  ctor: vi.fn(),
  uploads: [] as { opts: { onError: (e: unknown) => void; onSuccess: () => void } }[],
}));
vi.mock("tus-js-client", () => ({
  Upload: class {
    opts: unknown;
    constructor(file: unknown, opts: unknown) { ctor(file, opts); this.opts = opts; uploads.push(this as never); }
    findPreviousUploads = () => Promise.resolve([]);
    resumeFromPreviousUpload = vi.fn();
    start = vi.fn();
    abort = vi.fn();
  },
}));

import i18n from "../../i18n";
import UploadPage from "./Upload";

const landing = { owner_name: "Alice", message: "send me stuff", expires_at: "2030-01-01T00:00:00Z", max_files: 5, max_total_bytes: 1024 ** 3, allowed_exts: ["pdf", "docx"] };
const mine = { files: [{ id: "f1", name: "old.pdf", size: 2048, created_at: "2030-01-01T00:00:00Z" }], files_left: 3, bytes_left: 5 * 1024 };
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status });

// `filesAfter` answers GET /files once verified (last one repeats); before that it is 401
function mockApi(filesAfter: Response[] = [json(200, mine)]) {
  let authed = false, n = 0;
  const f = vi.fn(async (url: string) => {
    if (url.endsWith("/files")) return authed ? filesAfter[Math.min(n++, filesAfter.length - 1)].clone() : json(401, { error: "unauthorized" });
    if (url.endsWith("/code")) return json(200, { sent: true });
    if (url.endsWith("/verify")) { authed = true; return json(200, mine); }
    if (url.endsWith("/logout")) { authed = false; return new Response(null, { status: 204 }); }
    return json(200, landing);
  });
  vi.stubGlobal("fetch", f);
  return f;
}
const renderPage = () =>
  render(<MemoryRouter initialEntries={["/r/tok"]}><Routes><Route path="/r/:token" element={<UploadPage />} /></Routes></MemoryRouter>);

async function toUpload() {
  fireEvent.change(await screen.findByLabelText(i18n.t("intake.email")), { target: { value: "up@x.com" } });
  fireEvent.click(screen.getByRole("button", { name: i18n.t("intake.sendCode") }));
  fireEvent.change(await screen.findByLabelText(i18n.t("intake.code")), { target: { value: "123456" } });
  fireEvent.click(screen.getByRole("button", { name: i18n.t("intake.verify") }));
  await screen.findByText("old.pdf");
}
const pick = (container: HTMLElement, ...files: File[]) =>
  fireEvent.change(container.querySelector("input[type=file]")!, { target: { files } });
const pdf = (name = "a.pdf", size = 10) => new File([new Uint8Array(size)], name);
const tusErr = (status: number, body: string) => ({ originalResponse: { getStatus: () => status, getBody: () => body } });

beforeEach(() => i18n.changeLanguage("en"));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.clearAllMocks(); uploads.length = 0; });

test("email → code → upload step shows limits", async () => {
  mockApi();
  renderPage();
  expect(await screen.findByText("send me stuff")).toBeTruthy();
  expect(screen.getByText(i18n.t("intake.from", { name: "Alice" }))).toBeTruthy();
  await toUpload();
  expect(screen.getByText(i18n.t("intake.allowedExts", { exts: "pdf, docx" }))).toBeTruthy();
  expect(screen.getByText(i18n.t("intake.filesLeft", { count: 3 }))).toBeTruthy();
  expect(screen.getByText(i18n.t("intake.bytesLeft", { size: "5 KB" }))).toBeTruthy();
  expect(screen.getByText("2 KB")).toBeTruthy();
});

test("an existing session goes straight to the upload step, accept follows the extensions", async () => {
  vi.stubGlobal("fetch", vi.fn(async (url: string) => (url.endsWith("/files") ? json(200, mine) : json(200, landing))));
  const { container } = renderPage();
  await screen.findByText("old.pdf");
  expect(container.querySelector("input[type=file]")!.getAttribute("accept")).toBe(".pdf,.docx");
});

test("rejects disallowed extension before upload", async () => {
  mockApi();
  const { container } = renderPage();
  await toUpload();
  pick(container, pdf("evil.exe"), pdf("noext"));
  expect((await screen.findAllByRole("alert")).map((a) => a.textContent)).toEqual([i18n.t("intake.error.extNotAllowed"), i18n.t("intake.error.extNotAllowed")]);
  expect(ctor).not.toHaveBeenCalled();
});

test("any extension is accepted when the request has no list", async () => {
  vi.stubGlobal("fetch", vi.fn(async (url: string) => (url.endsWith("/files") ? json(200, mine) : json(200, { ...landing, allowed_exts: [] }))));
  const { container } = renderPage();
  await screen.findByText("old.pdf");
  expect(container.querySelector("input[type=file]")!.hasAttribute("accept")).toBe(false);
  expect(screen.getByText(i18n.t("intake.allowedExts", { exts: i18n.t("intake.anyExt") }))).toBeTruthy();
  pick(container, pdf("x.exe"));
  await waitFor(() => expect(ctor).toHaveBeenCalledTimes(1));
});

test("rejects once files left are used up, counting files queued in this session", async () => {
  mockApi([json(200, { ...mine, files_left: 1 })]);
  const { container } = renderPage();
  await toUpload();
  pick(container, pdf("a.pdf", 50), pdf("b.pdf", 10));
  await waitFor(() => expect(ctor).toHaveBeenCalledTimes(1));
  expect((await screen.findByRole("alert")).textContent).toBe(i18n.t("intake.error.tooManyFiles"));
});

test("rejects once bytes left are used up, counting bytes queued in this session", async () => {
  mockApi([json(200, { ...mine, bytes_left: 100 })]);
  const { container } = renderPage();
  await toUpload();
  pick(container, pdf("a.pdf", 60), pdf("b.pdf", 60));
  await waitFor(() => expect(ctor).toHaveBeenCalledTimes(1));
  expect((await screen.findByRole("alert")).textContent).toBe(i18n.t("intake.error.quotaExceeded"));
});

test("a finished upload refreshes the list", async () => {
  const f = mockApi([json(200, mine), json(200, { ...mine, files: [...mine.files, { id: "f2", name: "new.pdf", size: 1, created_at: "2030-01-01T00:00:00Z" }] })]);
  const { container } = renderPage();
  await toUpload();
  pick(container, pdf());
  await waitFor(() => expect(uploads).toHaveLength(1));
  expect(ctor.mock.calls[0][1].endpoint).toBe("/api/r/tok/uploads/");
  act(() => uploads[0].opts.onSuccess());
  expect(await screen.findByText("new.pdf")).toBeTruthy();
  expect(f.mock.calls.filter(([u]) => u === "/api/r/tok/files").length).toBeGreaterThanOrEqual(2);
});

test("upload failure re-checks session", async () => {
  // the /files re-check after the failure answers 401: the session ended
  const f = mockApi([json(200, mine), json(401, { error: "unauthorized" })]);
  const { container } = renderPage();
  await toUpload();
  pick(container, pdf());
  await waitFor(() => expect(uploads).toHaveLength(1));
  act(() => uploads[0].opts.onError(tusErr(401, "")));
  expect((await screen.findByRole("alert")).textContent).toBe(i18n.t("intake.error.sessionEnded"));
  expect(screen.getByLabelText(i18n.t("intake.email"))).toBeTruthy();
  expect(f.mock.calls.filter(([u]) => u === "/api/r/tok/files").length).toBe(3);
});

test("a 410 whose re-check says gone shows the gone reason", async () => {
  mockApi([json(200, mine), json(410, { error: "gone" })]);
  const { container } = renderPage();
  await toUpload();
  pick(container, pdf());
  await waitFor(() => expect(uploads).toHaveLength(1));
  act(() => uploads[0].opts.onError(tusErr(410, "")));
  expect((await screen.findByRole("alert")).textContent).toBe(i18n.t("intake.error.gone"));
});

test.each([
  ["quota_exceeded", "quotaExceeded"],
  ["ext_not_allowed", "extNotAllowed"],
  ["too_many_files", "tooManyFiles"],
])("%s error shows message", async (body, key) => {
  mockApi();
  const { container } = renderPage();
  await toUpload();
  pick(container, pdf());
  await waitFor(() => expect(uploads).toHaveLength(1));
  act(() => uploads[0].opts.onError(tusErr(403, body)));
  expect((await screen.findByRole("alert")).textContent).toBe(i18n.t(`intake.error.${key}`));
});

test("a network error without a response shows nothing extra", async () => {
  mockApi();
  const { container } = renderPage();
  await toUpload();
  pick(container, pdf());
  await waitFor(() => expect(uploads).toHaveLength(1));
  act(() => uploads[0].opts.onError(new Error("offline")));
  expect(screen.queryByRole("alert")).toBeNull();
});

test("resend, change email, then leave logs out", async () => {
  const f = mockApi();
  renderPage();
  fireEvent.change(await screen.findByLabelText(i18n.t("intake.email")), { target: { value: "up@x.com" } });
  fireEvent.click(screen.getByRole("button", { name: i18n.t("intake.sendCode") }));
  expect((await screen.findByRole("status")).textContent).toBe(i18n.t("intake.codeSent"));
  fireEvent.click(screen.getByRole("button", { name: i18n.t("intake.resend") }));
  await waitFor(() => expect(f.mock.calls.filter(([u]) => u.endsWith("/code"))).toHaveLength(2));
  fireEvent.click(await screen.findByRole("button", { name: i18n.t("intake.changeEmail") }));
  fireEvent.click(await screen.findByRole("button", { name: i18n.t("intake.sendCode") }));
  fireEvent.change(await screen.findByLabelText(i18n.t("intake.code")), { target: { value: "123456" } });
  fireEvent.click(screen.getByRole("button", { name: i18n.t("intake.verify") }));
  await screen.findByText("old.pdf");
  fireEvent.click(screen.getByRole("button", { name: i18n.t("intake.leave") }));
  expect(await screen.findByLabelText(i18n.t("intake.email"))).toBeTruthy();
  expect(f).toHaveBeenCalledWith("/api/r/tok/logout", expect.objectContaining({ method: "POST" }));
});

test.each([
  [404, "notFound"],
  [410, "gone"],
  [429, "rateLimited"],
  [500, "generic"],
])("landing %i is fatal", async (status, key) => {
  vi.stubGlobal("fetch", vi.fn(async () => json(status, { error: "x" })));
  renderPage();
  expect((await screen.findByRole("alert")).textContent).toBe(i18n.t(`intake.error.${key}`));
});

test("wrong code shows the invalid-code message", async () => {
  vi.stubGlobal("fetch", vi.fn(async (url: string) => {
    if (url.endsWith("/files")) return json(401, { error: "unauthorized" });
    if (url.endsWith("/code")) return json(200, { sent: true });
    if (url.endsWith("/verify")) return json(401, { error: "invalid_code" });
    return json(200, landing);
  }));
  renderPage();
  fireEvent.change(await screen.findByLabelText(i18n.t("intake.email")), { target: { value: "up@x.com" } });
  fireEvent.click(screen.getByRole("button", { name: i18n.t("intake.sendCode") }));
  fireEvent.change(await screen.findByLabelText(i18n.t("intake.code")), { target: { value: "000000" } });
  fireEvent.click(screen.getByRole("button", { name: i18n.t("intake.verify") }));
  expect((await screen.findByRole("alert")).textContent).toBe(i18n.t("intake.error.invalidCode"));
});
