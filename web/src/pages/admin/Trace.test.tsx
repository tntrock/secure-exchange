import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import i18n from "../../i18n";
import Trace from "./Trace";

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status });
const hit = {
  source: "download", via: "code", code: "ABCDEFGHJK", file_id: "f1", file_name: "plan.pdf", share_id: "s1",
  owner_email: "owner@x.com", recipient_email: "leaker@x.com", ip: "1.2.3.4", at: "2030-01-01T00:00:00Z", method: "pdf_pages",
};
const mock = (body: unknown, status = 200) => {
  const f = vi.fn(async (_u: string, _i?: RequestInit) => json(status, body));
  vi.stubGlobal("fetch", f);
  return f;
};

beforeEach(() => i18n.changeLanguage("en"));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

test("code lookup posts {code} and lists the hit", async () => {
  const f = mock({ hits: [hit], analyzed: false, sha256: "" });
  render(<Trace />);
  fireEvent.change(screen.getByLabelText(i18n.t("trace.code")), { target: { value: " abcdefghjk " } });
  fireEvent.click(screen.getAllByRole("button", { name: i18n.t("trace.search") })[0]);
  expect(await screen.findByText("leaker@x.com")).toBeTruthy();
  expect(f.mock.calls[0][0]).toBe("/api/admin/trace");
  expect(JSON.parse(f.mock.calls[0][1]!.body as string)).toEqual({ code: "abcdefghjk" });
  expect(screen.getByText("owner@x.com")).toBeTruthy();
  expect(screen.queryByText(i18n.t("trace.notAnalyzed"))).toBeNull();
});

test("sha256 lookup posts {sha256}", async () => {
  const f = mock({ hits: [hit], analyzed: false });
  render(<Trace />);
  fireEvent.change(screen.getByLabelText(i18n.t("trace.sha256")), { target: { value: "ab12" } });
  fireEvent.click(screen.getAllByRole("button", { name: i18n.t("trace.search") })[1]);
  await screen.findByText("leaker@x.com");
  expect(JSON.parse(f.mock.calls[0][1]!.body as string)).toEqual({ sha256: "ab12" });
  expect(screen.queryByText(i18n.t("trace.notAnalyzed"))).toBeNull();
});

test("empty result shows undetermined", async () => {
  mock({ hits: [], analyzed: false });
  render(<Trace />);
  fireEvent.change(screen.getByLabelText(i18n.t("trace.code")), { target: { value: "x" } });
  fireEvent.click(screen.getAllByRole("button", { name: i18n.t("trace.search") })[0]);
  expect(await screen.findByText(i18n.t("trace.undetermined"))).toBeTruthy();
});

test("file upload is sent as FormData", async () => {
  const f = mock({ hits: [], analyzed: true });
  render(<Trace />);
  const file = new File(["data"], "leak.png", { type: "image/png" });
  fireEvent.change(screen.getByLabelText(i18n.t("trace.file")), { target: { files: [file] } });
  fireEvent.click(screen.getAllByRole("button", { name: i18n.t("trace.search") })[2]);
  await waitFor(() => expect(f).toHaveBeenCalled());
  const body = f.mock.calls[0][1]!.body as FormData;
  expect(body).toBeInstanceOf(FormData);
  expect((body.get("file") as File).name).toBe("leak.png");
  expect((f.mock.calls[0][1]!.headers as Record<string, string> | undefined)?.["Content-Type"]).toBeUndefined();
});

test("search with nothing entered does nothing; errors are shown", async () => {
  const f = mock({ error: "bad_code" }, 400);
  render(<Trace />);
  fireEvent.click(screen.getAllByRole("button", { name: i18n.t("trace.search") })[2]);
  expect(f).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText(i18n.t("trace.code")), { target: { value: "bad" } });
  fireEvent.click(screen.getAllByRole("button", { name: i18n.t("trace.search") })[0]);
  expect((await screen.findByRole("alert")).textContent).toBe(i18n.t("trace.error"));
});

test.each([[false, true], [true, false]])("file upload with analyzed=%s shows the not-analysed note: %s", async (analyzed, note) => {
  mock({ hits: [], analyzed });
  render(<Trace />);
  fireEvent.change(screen.getByLabelText(i18n.t("trace.file")), { target: { files: [new File(["d"], "x.bin")] } });
  fireEvent.click(screen.getAllByRole("button", { name: i18n.t("trace.search") })[2]);
  await screen.findByText(i18n.t("trace.undetermined"));
  expect(!!screen.queryByText(i18n.t("trace.notAnalyzed"))).toBe(note);
});

test("403 shows the forbidden message", async () => {
  mock({ error: "forbidden" }, 403);
  render(<Trace />);
  fireEvent.change(screen.getByLabelText(i18n.t("trace.code")), { target: { value: "x" } });
  fireEvent.click(screen.getAllByRole("button", { name: i18n.t("trace.search") })[0]);
  expect((await screen.findByRole("alert")).textContent).toBe(i18n.t("trace.forbidden"));
});

test("source, via and method are shown translated, for every value in both languages", async () => {
  mock({ hits: [hit], analyzed: false });
  render(<Trace />);
  fireEvent.change(screen.getByLabelText(i18n.t("trace.code")), { target: { value: "x" } });
  fireEvent.click(screen.getAllByRole("button", { name: i18n.t("trace.search") })[0]);
  await screen.findByText("leaker@x.com");
  expect(screen.getByText(`${i18n.t("trace.source.download")} / ${i18n.t("trace.via.code")}`)).toBeTruthy();
  expect(screen.getByText(i18n.t("trace.method.pdf_pages"))).toBeTruthy();
  expect(screen.queryByText("pdf_pages")).toBeNull();
  const keys = [
    ...["download", "view", "file"].map((v) => `trace.source.${v}`),
    ...["code", "metadata", "text_layer", "invisible", "sha256"].map((v) => `trace.via.${v}`),
    ...["pdf_pages", "pdf_meta", "image_visible", "image_invisible", "ooxml_meta", "odf_meta", "none"].map((v) => `trace.method.${v}`),
  ];
  for (const lng of ["en", "zh-TW"]) for (const k of keys) expect(i18n.exists(k, { lng }), `${lng} ${k}`).toBe(true);
});

test("a view hit has no method and shows an empty cell", async () => {
  mock({ hits: [{ ...hit, source: "view", method: "" }], analyzed: false });
  render(<Trace />);
  fireEvent.change(screen.getByLabelText(i18n.t("trace.code")), { target: { value: "x" } });
  fireEvent.click(screen.getAllByRole("button", { name: i18n.t("trace.search") })[0]);
  await screen.findByText("leaker@x.com");
  expect(screen.getByText(i18n.t("trace.source.view"), { exact: false })).toBeTruthy();
  expect(screen.queryByText(/trace\.method/)).toBeNull();
});
