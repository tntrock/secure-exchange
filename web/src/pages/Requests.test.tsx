import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import i18n from "../i18n";
import Requests from "./Requests";

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status });
const row = {
  id: "r1", created_at: "2030-01-01T00:00:00Z", expires_at: "2030-01-08T00:00:00Z", revoked: false, expired: false,
  file_count: 3, total_bytes: 2048, max_files: 10, max_total_bytes: 10 * 1024 ** 3, uploader_count: 2,
};

function mockApi(post: Response = json(201, { ...row })) {
  const f = vi.fn(async (_url: string, init?: RequestInit) => (init?.method === "POST" ? post.clone() : json(200, [row])));
  vi.stubGlobal("fetch", f);
  return f;
}
const renderPage = () =>
  render(
    <MemoryRouter initialEntries={["/requests"]}>
      <Routes>
        <Route path="/requests" element={<Requests />} />
        <Route path="/requests/:id" element={<p>detail page</p>} />
      </Routes>
    </MemoryRouter>,
  );

beforeEach(() => i18n.changeLanguage("en"));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

test("creates a request with parsed emails and exts", async () => {
  const f = mockApi();
  renderPage();
  fireEvent.change(await screen.findByLabelText(i18n.t("requests.emails")), { target: { value: "a@x.com, b@y.com\n" } });
  fireEvent.change(screen.getByLabelText(i18n.t("requests.exts")), { target: { value: ".pdf, docx" } });
  fireEvent.change(screen.getByLabelText(i18n.t("requests.message")), { target: { value: "please" } });
  fireEvent.click(screen.getByRole("button", { name: i18n.t("requests.create") }));
  await screen.findByText("detail page");
  const call = f.mock.calls.find(([, i]) => i?.method === "POST")!;
  expect(call[0]).toBe("/api/requests");
  const body = JSON.parse(call[1]!.body as string);
  expect(body).toMatchObject({ emails: ["a@x.com", "b@y.com"], allowed_exts: ["pdf", "docx"], max_total_bytes: 10 * 1024 ** 3, max_files: 10, message: "please" });
  expect(new Date(body.expires_at).getTime()).toBeGreaterThan(Date.now() + 6 * 864e5);
});

test("validation error shows under the form", async () => {
  mockApi(json(422, { error: "validation", field: "emails", code: "invalid" }));
  renderPage();
  fireEvent.change(await screen.findByLabelText(i18n.t("requests.emails")), { target: { value: "bad" } });
  fireEvent.click(screen.getByRole("button", { name: i18n.t("requests.create") }));
  expect((await screen.findByRole("alert")).textContent).toBe(i18n.t("requests.error.emails.invalid"));
});

test("an unknown error shows the generic message", async () => {
  mockApi(json(500, { error: "boom" }));
  renderPage();
  fireEvent.change(await screen.findByLabelText(i18n.t("requests.emails")), { target: { value: "a@x.com" } });
  fireEvent.click(screen.getByRole("button", { name: i18n.t("requests.create") }));
  expect((await screen.findByRole("alert")).textContent).toBe(i18n.t("requests.error.generic"));
});

test("lists requests with usage", async () => {
  mockApi();
  renderPage();
  expect(await screen.findByText("3 / 10")).toBeTruthy();
  expect(screen.getByText("2 KB / 10 GB")).toBeTruthy();
  expect(screen.getByText(i18n.t("requests.status.active"))).toBeTruthy();
  await waitFor(() => expect(screen.getAllByRole("link").some((a) => a.getAttribute("href") === "/requests/r1")).toBe(true));
});

test("empty list and list failure", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => json(200, null)));
  renderPage();
  expect(await screen.findByText(i18n.t("requests.empty"))).toBeTruthy();
  cleanup();
  vi.stubGlobal("fetch", vi.fn(async () => json(500, { error: "x" })));
  renderPage();
  expect((await screen.findByRole("alert")).textContent).toBe(i18n.t("app.error"));
});

test("the expiry input is limited to tomorrow..30 days and the last day stays under the server cap", async () => {
  const f = mockApi();
  renderPage();
  const day = (await screen.findByLabelText(i18n.t("requests.expiresOn"))) as HTMLInputElement;
  expect(day.min).toMatch(/^\d{4}-\d\d-\d\d$/);
  expect(day.max).toMatch(/^\d{4}-\d\d-\d\d$/);
  expect(day.min < day.max).toBe(true);
  fireEvent.change(day, { target: { value: day.max } });
  fireEvent.change(screen.getByLabelText(i18n.t("requests.emails")), { target: { value: "a@x.com" } });
  fireEvent.click(screen.getByRole("button", { name: i18n.t("requests.create") }));
  await screen.findByText("detail page");
  const body = JSON.parse(f.mock.calls.find(([, i]) => i?.method === "POST")![1]!.body as string);
  expect(new Date(body.expires_at).getTime()).toBeLessThanOrEqual(Date.now() + 30 * 864e5);
});
