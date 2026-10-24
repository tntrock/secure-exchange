import { afterEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, waitFor } from "@testing-library/react";

const ctor = vi.fn();
vi.mock("tus-js-client", () => ({
  Upload: class {
    constructor(file: unknown, opts: unknown) {
      ctor(file, opts);
    }
    findPreviousUploads = () => Promise.resolve([]);
    resumeFromPreviousUpload = vi.fn();
    start = vi.fn();
    abort = vi.fn();
  },
}));
vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (k: string) => k }) }));

import Uploader from "./Uploader";

afterEach(cleanup);

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
