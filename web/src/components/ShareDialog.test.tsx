import { afterEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
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
