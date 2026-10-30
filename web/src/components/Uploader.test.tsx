import { afterEach, expect, test, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

interface Opts { onProgress: (s: number, t: number) => void; onSuccess: () => void; onError: () => void }
const { ctor, uploads, prev } = vi.hoisted(() => ({
  ctor: vi.fn(),
  uploads: [] as { opts: Opts; start: ReturnType<typeof vi.fn>; abort: ReturnType<typeof vi.fn>; resumeFromPreviousUpload: ReturnType<typeof vi.fn>; found?: Promise<unknown[]> }[],
  prev: { list: [] as unknown[] },
}));
vi.mock("tus-js-client", () => ({
  Upload: class {
    opts: unknown;
    constructor(file: unknown, opts: unknown) {
      ctor(file, opts);
      this.opts = opts;
      uploads.push(this as never);
    }
    found?: Promise<unknown[]>;
    findPreviousUploads = () => (this.found = Promise.resolve(prev.list));
    resumeFromPreviousUpload = vi.fn();
    start = vi.fn();
    abort = vi.fn();
  },
}));
vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (k: string) => k }) }));

import Uploader from "./Uploader";

afterEach(() => { cleanup(); uploads.length = 0; prev.list = []; vi.clearAllMocks(); });

const pick = (container: HTMLElement, ...names: string[]) =>
  fireEvent.change(container.querySelector("input[type=file]")!, { target: { files: names.map((n) => new File(["x"], n, { type: "text/plain" })) } });

test("starts a tus upload with chunkSize 64MiB and filename metadata", async () => {
  const { container } = render(<Uploader onDone={() => {}} />);
  const file = new File(["hello"], "hello.txt", { type: "text/plain" });
  fireEvent.change(container.querySelector("input[type=file]")!, { target: { files: [file] } });
  await waitFor(() => expect(ctor).toHaveBeenCalled());
  const [f, opts] = ctor.mock.calls[0];
  expect(f).toBe(file);
  expect(opts.endpoint).toBe("/api/uploads/");
  expect(opts.chunkSize).toBe(67108864);
  expect(opts.retryDelays).toEqual([0, 1000, 3000, 5000, 10000]);
  expect(opts.storeFingerprintForResuming).toBe(true);
  expect(opts.metadata).toEqual({ filename: "hello.txt", filetype: "text/plain" });
});

test("resumes a previous upload of the same file before starting", async () => {
  prev.list = [{ uploadUrl: "/api/uploads/abc" }];
  const { container } = render(<Uploader onDone={() => {}} />);
  pick(container, "a.txt");
  await waitFor(() => expect(uploads[0]?.start).toHaveBeenCalled());
  expect(uploads[0].resumeFromPreviousUpload).toHaveBeenCalledWith(prev.list[0]);
});

test("progress, success calls onDone and hides the buttons", async () => {
  const onDone = vi.fn();
  const { container } = render(<Uploader onDone={onDone} />);
  pick(container, "a.txt");
  await waitFor(() => expect(uploads[0]?.start).toHaveBeenCalled());
  expect(uploads[0].resumeFromPreviousUpload).not.toHaveBeenCalled();
  act(() => uploads[0].opts.onProgress(0, 0));
  expect(screen.getByText("0%")).toBeTruthy();
  act(() => uploads[0].opts.onProgress(50, 200));
  expect(screen.getByText("25%")).toBeTruthy();
  act(() => uploads[0].opts.onSuccess());
  expect(screen.getByText("upload.done")).toBeTruthy();
  expect(onDone).toHaveBeenCalledOnce();
  expect(screen.queryByRole("button")).toBeNull();
});

test("pause aborts, resume restarts, error allows retry", async () => {
  const { container } = render(<Uploader onDone={() => {}} />);
  pick(container, "a.txt");
  await waitFor(() => expect(uploads[0]?.start).toHaveBeenCalledOnce());
  const u = uploads[0];
  fireEvent.click(screen.getByRole("button", { name: "upload.pause" }));
  expect(u.abort).toHaveBeenCalledWith();
  fireEvent.click(screen.getByRole("button", { name: "upload.resume" }));
  expect(u.start).toHaveBeenCalledTimes(2);
  act(() => u.opts.onError());
  expect(screen.getByText("upload.failed")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "upload.resume" }));
  expect(u.start).toHaveBeenCalledTimes(3);
  expect(screen.getByRole("button", { name: "upload.pause" })).toBeTruthy();
});

test("cancel terminates the upload and removes the row", async () => {
  const { container } = render(<Uploader onDone={() => {}} />);
  pick(container, "a.txt");
  await waitFor(() => expect(uploads[0]?.start).toHaveBeenCalled());
  fireEvent.click(screen.getByRole("button", { name: "upload.cancel" }));
  expect(uploads[0].abort).toHaveBeenCalledWith(true);
  expect(screen.queryByText("a.txt")).toBeNull();
});

test("unmount before the resume lookup settles never starts the upload", async () => {
  const { container, unmount } = render(<Uploader onDone={() => {}} />);
  pick(container, "a.txt");
  const u = uploads[0];
  unmount();
  expect(u.found).toBeDefined();
  await u.found; // the component's .then on this promise was registered first, so it has run
  expect(u.abort).toHaveBeenCalled();
  expect(u.start).not.toHaveBeenCalled();
});

test("drag highlights the drop zone and drop adds files; click opens the picker", () => {
  const { container } = render(<Uploader onDone={() => {}} />);
  const zone = container.querySelector(".drop")!;
  fireEvent.dragOver(zone);
  expect(zone.className).toBe("drop over");
  fireEvent.dragLeave(zone);
  expect(zone.className).toBe("drop");
  fireEvent.dragOver(zone);
  fireEvent.drop(zone, { dataTransfer: { files: [new File(["x"], "d1.txt"), new File(["y"], "d2.txt")] } });
  expect(zone.className).toBe("drop");
  expect(screen.getByText("d1.txt")).toBeTruthy();
  expect(screen.getByText("d2.txt")).toBeTruthy();
  const input = container.querySelector("input[type=file]") as HTMLInputElement;
  const click = vi.spyOn(input, "click");
  fireEvent.click(zone);
  expect(click).toHaveBeenCalled();
});
