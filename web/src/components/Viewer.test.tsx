import { afterEach, expect, test, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import i18n from "../i18n";
import Viewer, { lowestVisible } from "./Viewer";

const loadSource = vi.fn(), attachMedia = vi.fn(), destroy = vi.fn(), on = vi.fn(), isSupported = vi.fn();
const supported = { value: true };
vi.mock("hls.js", () => ({
  default: class { static isSupported() { isSupported(); return supported.value; } static Events = { ERROR: "hlsError" }; on = on; loadSource = loadSource; attachMedia = attachMedia; destroy = destroy; },
}));

afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.clearAllMocks(); });

const stub = (status: number, body: unknown) =>
  vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(new Response(JSON.stringify(body), { status }))));

test("pages: renders img per page, keys page and zoom, Esc closes", async () => {
  stub(200, { kind: "pages", status: "ready", page_count: 3 });
  const onClose = vi.fn();
  render(<Viewer base="/api/files/f1/preview" onClose={onClose} />);
  const imgs = await screen.findAllByRole("img");
  expect(imgs).toHaveLength(3);
  expect(imgs[0].getAttribute("src")).toBe("/api/files/f1/preview/pages/0");
  expect(imgs[2].getAttribute("src")).toBe("/api/files/f1/preview/pages/2");
  expect(imgs[0].getAttribute("data-page")).toBe("1");
  expect(imgs[0].getAttribute("draggable")).toBe("false");
  expect(screen.getByText("1 / 3")).toBeTruthy();
  const dlg = screen.getByRole("dialog");
  fireEvent.keyDown(dlg, { key: "ArrowRight" });
  expect(screen.getByText("2 / 3")).toBeTruthy();
  fireEvent.keyDown(dlg, { key: "+" });
  expect(screen.getByText("125%")).toBeTruthy();
  fireEvent.keyDown(dlg, { key: "Escape" });
  expect(onClose).toHaveBeenCalled();
});

test("video: hls.js loads the m3u8", async () => {
  stub(200, { kind: "video", status: "ready", page_count: 0 });
  const { container } = render(<Viewer base="/api/s/tk/files/f1/preview" onClose={() => {}} />);
  await waitFor(() => expect(loadSource).toHaveBeenCalledWith("/api/s/tk/files/f1/preview/video.m3u8"));
  expect(container.querySelector("video")).toBeTruthy();
  cleanup();
  expect(destroy).toHaveBeenCalled();
});

test("pending shows processing message", async () => {
  stub(200, { kind: "pages", status: "pending", page_count: 0 });
  render(<Viewer base="/b" onClose={() => {}} />);
  expect(await screen.findByText(i18n.t("viewer.pending"))).toBeTruthy();
});

test("401 calls onSessionEnded", async () => {
  stub(401, { error: "session" });
  const ended = vi.fn();
  render(<Viewer base="/b" onClose={() => {}} onSessionEnded={ended} />);
  await waitFor(() => expect(ended).toHaveBeenCalled());
});

test("403 view_limit / ip_denied and 422 not_previewable have own messages", async () => {
  stub(403, { error: "view_limit" });
  render(<Viewer base="/b" onClose={() => {}} />);
  expect(await screen.findByText(i18n.t("viewer.view_limit"))).toBeTruthy();
  cleanup();
  stub(422, { error: "not_previewable" });
  render(<Viewer base="/b" onClose={() => {}} />);
  expect(await screen.findByText(i18n.t("viewer.notReady"))).toBeTruthy();
});

test("staff 401 shows re-login message", async () => {
  stub(401, { error: "unauthorized" });
  render(<Viewer base="/b" onClose={() => {}} />);
  expect(await screen.findByText(i18n.t("viewer.reLogin"))).toBeTruthy();
});

test("lowestVisible picks the lowest page", () => {
  expect(lowestVisible([])).toBeNull();
  expect(lowestVisible(new Set([5, 3, 4]))).toBe(3);
});

test("image: single img requests pages/0", async () => {
  stub(200, { kind: "image", status: "ready", page_count: 1, width: 800, height: 600 });
  render(<Viewer base="/api/files/f1/preview" onClose={() => {}} />);
  const imgs = await screen.findAllByRole("img");
  expect(imgs).toHaveLength(1);
  expect(imgs[0].getAttribute("src")).toBe("/api/files/f1/preview/pages/0");
});

test("buttons and keys move pages and zoom within bounds", async () => {
  stub(200, { kind: "pages", status: "ready", page_count: 2 });
  render(<Viewer base="/b" onClose={() => {}} />);
  const prev = (await screen.findByRole("button", { name: "Previous page" })) as HTMLButtonElement;
  const next = screen.getByRole("button", { name: "Next page" }) as HTMLButtonElement;
  const out = screen.getByRole("button", { name: "Zoom out" }) as HTMLButtonElement;
  expect(prev.disabled).toBe(true);
  fireEvent.click(next);
  expect(screen.getByText("2 / 2")).toBeTruthy();
  expect(next.disabled).toBe(true);
  const dlg = screen.getByRole("dialog");
  fireEvent.keyDown(dlg, { key: "PageDown" }); // clamped at the last page
  expect(screen.getByText("2 / 2")).toBeTruthy();
  fireEvent.keyDown(dlg, { key: "PageUp" });
  expect(screen.getByText("1 / 2")).toBeTruthy();
  fireEvent.click(next);
  fireEvent.keyDown(dlg, { key: "ArrowLeft" });
  expect(screen.getByText("1 / 2")).toBeTruthy();
  fireEvent.click(out);
  fireEvent.keyDown(dlg, { key: "-" });
  expect(screen.getByText("50%")).toBeTruthy();
  expect(out.disabled).toBe(true);
  for (let i = 0; i < 12; i++) fireEvent.click(screen.getByRole("button", { name: "Zoom in" }));
  fireEvent.keyDown(dlg, { key: "=" });
  expect(screen.getByText("300%")).toBeTruthy();
  // unrelated keys are not swallowed
  expect(fireEvent.keyDown(dlg, { key: "a" })).toBe(true);
  expect(fireEvent.keyDown(dlg, { key: "+" })).toBe(false);
  fireEvent.click(next);
  fireEvent.click(prev);
  expect(screen.getByText("1 / 2")).toBeTruthy();
  // no context menu (save image as...)
  expect(fireEvent.contextMenu(dlg)).toBe(false);
});

test("keys other than Escape are ignored while nothing is shown", async () => {
  stub(200, { kind: "pages", status: "pending", page_count: 0 });
  render(<Viewer base="/b" onClose={() => {}} />);
  expect(screen.getByText(i18n.t("app.loading"))).toBeTruthy();
  expect(fireEvent.keyDown(screen.getByRole("dialog"), { key: "ArrowRight" })).toBe(true);
  await screen.findByText(i18n.t("viewer.pending"));
});

test.each([
  [410, "gone", "viewer.gone"],
  [409, "x", "viewer.pending"],
  [403, "ip_denied", "viewer.ip_denied"],
  [403, "other", "viewer.error"],
  [500, "x", "viewer.error"],
])("status %i (%s) maps to %s", async (status, error, key) => {
  stub(status, { error });
  render(<Viewer base="/b" onClose={() => {}} />);
  expect(await screen.findByText(i18n.t(key))).toBeTruthy();
});

test("non-ready preview status shows notReady; fetch failure shows error", async () => {
  stub(200, { kind: "pages", status: "failed", page_count: 0 });
  render(<Viewer base="/b" onClose={() => {}} />);
  expect(await screen.findByText(i18n.t("viewer.notReady"))).toBeTruthy();
  cleanup();
  vi.stubGlobal("fetch", vi.fn(() => Promise.reject(new TypeError("offline"))));
  render(<Viewer base="/b" onClose={() => {}} />);
  expect(await screen.findByText(i18n.t("viewer.error"))).toBeTruthy();
});

test("a broken page image re-checks the info URL once and shows why", async () => {
  const f = vi.fn()
    .mockResolvedValueOnce(new Response(JSON.stringify({ kind: "pages", status: "ready", page_count: 2 }), { status: 200 }))
    .mockResolvedValue(new Response(JSON.stringify({ error: "gone" }), { status: 410 }));
  vi.stubGlobal("fetch", f);
  render(<Viewer base="/b" onClose={() => {}} />);
  const imgs = await screen.findAllByRole("img");
  fireEvent.error(imgs[0]);
  fireEvent.error(imgs[1]);
  expect(await screen.findByText(i18n.t("viewer.gone"))).toBeTruthy();
  expect(f).toHaveBeenCalledTimes(2);
});

test("a broken page image whose re-check fails keeps the pages", async () => {
  const ok = new Response(JSON.stringify({ kind: "pages", status: "ready", page_count: 1 }), { status: 200 });
  const f = vi.fn().mockResolvedValueOnce(ok).mockRejectedValueOnce(new TypeError("offline"));
  vi.stubGlobal("fetch", f);
  render(<Viewer base="/b" onClose={() => {}} />);
  fireEvent.error(await screen.findByRole("img"));
  await waitFor(() => expect(f).toHaveBeenCalledTimes(2));
  expect(screen.queryByRole("alert")).toBeNull();
  expect(screen.getByRole("img")).toBeTruthy();
});

test("video: native HLS support sets src directly without hls.js", async () => {
  const can = vi.spyOn(HTMLMediaElement.prototype, "canPlayType").mockReturnValue("maybe");
  stub(200, { kind: "video", status: "ready", page_count: 0 });
  const { container } = render(<Viewer base="/v" onClose={() => {}} />);
  await waitFor(() => expect(container.querySelector("video")?.getAttribute("src")).toBe("/v/video.m3u8"));
  expect(loadSource).not.toHaveBeenCalled();
  // video has no page controls and ignores page keys
  expect(screen.queryByRole("button", { name: "Next page" })).toBeNull();
  expect(fireEvent.keyDown(screen.getByRole("dialog"), { key: "ArrowRight" })).toBe(true);
  can.mockRestore();
});

test("video: a fatal hls.js error is reported, non-fatal ones are not", async () => {
  stub(200, { kind: "video", status: "ready", page_count: 0 });
  const ended = vi.fn();
  render(<Viewer base="/v" onClose={() => {}} onSessionEnded={ended} />);
  await waitFor(() => expect(on).toHaveBeenCalled());
  const [ev, handler] = on.mock.calls[0];
  expect(ev).toBe("hlsError");
  act(() => handler(null, { fatal: false, response: { code: 401 } }));
  expect(ended).not.toHaveBeenCalled();
  act(() => handler(null, { fatal: true, response: { code: 401 } }));
  expect(ended).toHaveBeenCalled();
  expect(await screen.findByText(i18n.t("viewer.ended"))).toBeTruthy();
  act(() => handler(null, { fatal: true }));
  expect(await screen.findByText(i18n.t("viewer.error"))).toBeTruthy();
});

test("video: hls.js unsupported leaves the player alone", async () => {
  supported.value = false;
  try {
    stub(200, { kind: "video", status: "ready", page_count: 0 });
    const { container } = render(<Viewer base="/v" onClose={() => {}} />);
    await waitFor(() => expect(container.querySelector("video")).toBeTruthy());
    // isSupported() is the last step before loadSource: once it has answered, loadSource would have run
    await waitFor(() => expect(isSupported).toHaveBeenCalled());
    expect(loadSource).not.toHaveBeenCalled();
  } finally {
    supported.value = true;
  }
});

test("the page indicator follows the IntersectionObserver", async () => {
  let cb: (es: { target: Element; isIntersecting: boolean }[]) => void = () => {};
  const observe = vi.fn(), disconnect = vi.fn();
  vi.stubGlobal("IntersectionObserver", class { constructor(c: typeof cb) { cb = c; } observe = observe; disconnect = disconnect; });
  stub(200, { kind: "pages", status: "ready", page_count: 3 });
  render(<Viewer base="/b" onClose={() => {}} />);
  const imgs = await screen.findAllByRole("img");
  await waitFor(() => expect(observe).toHaveBeenCalledTimes(3));
  act(() => cb([{ target: imgs[2], isIntersecting: true }, { target: imgs[1], isIntersecting: true }]));
  expect(screen.getByText("2 / 3")).toBeTruthy();
  act(() => cb([{ target: imgs[1], isIntersecting: false }]));
  expect(screen.getByText("3 / 3")).toBeTruthy();
  act(() => cb([{ target: imgs[2], isIntersecting: false }]));
  expect(screen.getByText("3 / 3")).toBeTruthy();
  cleanup();
  expect(disconnect).toHaveBeenCalled();
});

test("unmount before the info request settles does not render a message", async () => {
  let resolve: (r: Response) => void = () => {};
  const pending = new Promise<Response>((r) => { resolve = r; });
  vi.stubGlobal("fetch", vi.fn(() => pending));
  const { unmount } = render(<Viewer base="/b" onClose={() => {}} />);
  unmount();
  const res = new Response(JSON.stringify({ error: "x" }), { status: 500 });
  const json = vi.spyOn(res, "json");
  resolve(res);
  await pending; // the component awaited this promise first, so its continuation has run
  expect(json).not.toHaveBeenCalled(); // it bailed out before reading the error body
  expect(document.body.textContent).toBe("");
});
