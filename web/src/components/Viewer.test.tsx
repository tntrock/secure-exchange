import { afterEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import i18n from "../i18n";
import Viewer from "./Viewer";

const loadSource = vi.fn(), attachMedia = vi.fn(), destroy = vi.fn();
vi.mock("hls.js", () => ({
  default: class { static isSupported() { return true; } loadSource = loadSource; attachMedia = attachMedia; destroy = destroy; },
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
  expect(imgs[1].getAttribute("src")).toBe("/api/files/f1/preview/pages/2");
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
