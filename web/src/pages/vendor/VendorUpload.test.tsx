import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import i18n from "../../i18n";

const { ctor } = vi.hoisted(() => ({ ctor: vi.fn() }));
vi.mock("tus-js-client", () => ({
  Upload: class {
    constructor(file: unknown, opts: unknown) { ctor(file, opts); }
    findPreviousUploads = () => Promise.resolve([]);
    start = vi.fn();
    abort = vi.fn();
  },
}));
import VendorUpload from "./VendorUpload";

const json = (b: unknown) => new Response(JSON.stringify(b));
const mock = (recips: unknown[]) => vi.stubGlobal("fetch", vi.fn(async (url: string) => (url.endsWith("recipients") ? json(recips) : json([{ id: "u1", name: "mine.pdf", size: 10, recipient_name: "Alice", created_at: "2030-01-01T00:00:00Z" }]))));
const pick = (c: HTMLElement) => fireEvent.change(c.querySelector("input[type=file]")!, { target: { files: [new File(["x"], "a.txt")] } });

beforeEach(() => i18n.changeLanguage("en"));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); ctor.mockClear(); });

test("uploader disabled until recipient chosen", async () => {
  mock([{ id: "r1", name: "Alice", email: "a@x.com" }]);
  const { container } = render(<VendorUpload />);
  await screen.findByRole("option", { name: /Alice/ });
  expect(container.querySelector("input[type=file]")).toBeNull();
  expect(screen.getByText("Choose a recipient first")).toBeTruthy();
  expect(await screen.findByText("mine.pdf")).toBeTruthy();
});

test("passes recipient metadata", async () => {
  mock([{ id: "r1", name: "Alice", email: "a@x.com" }]);
  const { container } = render(<VendorUpload />);
  await screen.findByRole("option", { name: /Alice/ });
  fireEvent.change(screen.getByLabelText("Recipient"), { target: { value: "r1" } });
  pick(container);
  await waitFor(() => expect(ctor).toHaveBeenCalled());
  expect(ctor.mock.calls[0][1].endpoint).toBe("/api/vendor/uploads/");
  expect(ctor.mock.calls[0][1].metadata).toMatchObject({ recipient: "r1", filename: "a.txt" });
});

test("empty recipients explains", async () => {
  mock([]);
  render(<VendorUpload />);
  expect(await screen.findByText(/Someone must share/)).toBeTruthy();
});

test("recipient_not_allowed shows a message", async () => {
  mock([{ id: "r1", name: "Alice", email: "a@x.com" }]);
  const { container } = render(<VendorUpload />);
  await screen.findByRole("option", { name: /Alice/ });
  fireEvent.change(screen.getByLabelText("Recipient"), { target: { value: "r1" } });
  pick(container);
  await waitFor(() => expect(ctor).toHaveBeenCalled());
  ctor.mock.calls[0][1].onError({ originalResponse: { getStatus: () => 403, getBody: () => "recipient_not_allowed" } });
  expect(await screen.findByText("You cannot upload to this recipient")).toBeTruthy();
});
