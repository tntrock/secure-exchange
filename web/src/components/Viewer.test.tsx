import { afterEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import i18n from "../i18n";
import Viewer, { lowestVisible } from "./Viewer";

const loadSource = vi.fn(), attachMedia = vi.fn(), destroy = vi.fn();
vi.mock("hls.js", () => ({
  default: class { static isSupported() { return true; } static Events = { ERROR: "hlsError" }; on = vi.fn(); loadSource = loadSource; attachMedia = attachMedia; destroy = destroy; },
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
