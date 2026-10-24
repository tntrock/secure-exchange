import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import i18n from "../../i18n";
import Access from "./Access";

const landing = { owner_name: "Alice", message: "hello there", expires_at: "2030-01-01T00:00:00Z" };
const filesBody = {
  message: "hello there", expires_at: "2030-01-01T00:00:00Z", allow_download: true, watermark: false,
  files: [{ id: "f1", name: "a.pdf", size: 2048, available: true }, { id: "f2", name: "gone.pdf", size: 1, available: false }],
};
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status });

function mockApi(verify: Response) {
  let authed = false;
  const f = vi.fn(async (url: string) => {
    if (url.endsWith("/files")) return authed ? json(200, filesBody) : json(401, { error: "unauthorized" });
    if (url.endsWith("/code")) return json(200, { sent: true });
    if (url.endsWith("/verify")) { authed = verify.ok; return verify; }
    return json(200, landing);
  });
  vi.stubGlobal("fetch", f);
  return f;
}

function renderPage() {
  render(<MemoryRouter initialEntries={["/s/tok"]}><Routes><Route path="/s/:token" element={<Access />} /></Routes></MemoryRouter>);
}

async function toVerify() {
  fireEvent.change(await screen.findByLabelText("Your email"), { target: { value: "bob@x.com" } });
  fireEvent.click(screen.getByRole("button", { name: "Send code" }));
  fireEvent.change(await screen.findByLabelText("6-digit code"), { target: { value: "123456" } });
  fireEvent.click(screen.getByRole("button", { name: "Verify" }));
}

beforeEach(() => i18n.changeLanguage("en"));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

test("email -> code -> file list with download links", async () => {
  mockApi(json(200, {}));
  renderPage();
  expect(await screen.findByText(/Alice/)).toBeTruthy();
  expect(screen.getByText("hello there")).toBeTruthy();
  await toVerify();
  const link = (await screen.findByRole("link", { name: /a\.pdf|Download/ })) as HTMLAnchorElement;
  expect(link.getAttribute("href")).toBe("/api/s/tok/files/f1/content");
  expect(screen.getAllByRole("link")).toHaveLength(1);
  expect(screen.getByText("Unavailable")).toBeTruthy();
});

test("invalid code shows error", async () => {
  mockApi(json(401, { error: "invalid_code" }));
  renderPage();
  await toVerify();
  expect(await screen.findByText("Incorrect or expired code")).toBeTruthy();
});

test("gone share shows message", async () => {
  vi.stubGlobal("fetch", vi.fn(async (url: string) => (url.endsWith("/files") ? json(401, { error: "unauthorized" }) : json(410, { error: "gone" }))));
  renderPage();
  expect(await screen.findByText("This share has expired or been revoked")).toBeTruthy();
});
