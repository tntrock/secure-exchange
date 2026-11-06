import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import i18n from "../i18n";
import Invite from "./Invite";

vi.mock("qrcode", () => ({ default: { toDataURL: vi.fn(async () => "data:image/png;base64,xx") } }));
const json = (s: number, b: unknown) => new Response(JSON.stringify(b), { status: s });
const info = { email: "v@x.com", otpauth_url: "otpauth://x" };
const show = () => render(<MemoryRouter initialEntries={["/invite/tk"]}><Routes><Route path="/invite/:token" element={<Invite />} /></Routes></MemoryRouter>);
const PW = "correct horse battery";
function fill(pw = PW, pw2 = PW) {
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: pw } });
  fireEvent.change(screen.getByLabelText("Confirm password"), { target: { value: pw2 } });
  fireEvent.change(screen.getByLabelText("Code (6 digits)"), { target: { value: "123456" } });
}
const submit = () => fireEvent.click(screen.getByRole("button", { name: "Activate account" }));

beforeEach(() => i18n.changeLanguage("en"));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

test("activates with password and code", async () => {
  const f = vi.fn(async (_u: string, init?: RequestInit) => (init?.method === "POST" ? new Response(null, { status: 204 }) : json(200, info)));
  vi.stubGlobal("fetch", f);
  show();
  expect(await screen.findByText(/v@x.com/)).toBeTruthy();
  await waitFor(() => expect(screen.getByRole("img")).toBeTruthy());
  fill();
  submit();
  expect(await screen.findByText(/Wait for your authenticator app to show a new code/)).toBeTruthy();
  const link = screen.getByRole("link", { name: "Log in" });
  expect(link.getAttribute("href")).toBe("/login");
  expect(f).toHaveBeenLastCalledWith("/api/invite/tk", expect.objectContaining({ body: JSON.stringify({ password: PW, code: "123456" }) }));
});

test("password mismatch blocks submit", async () => {
  const f = vi.fn(async () => json(200, info));
  vi.stubGlobal("fetch", f);
  show();
  await screen.findByText(/v@x.com/);
  fill(PW, PW + "x");
  submit();
  expect(await screen.findByText("Passwords do not match")).toBeTruthy();
  expect(f).toHaveBeenCalledTimes(1);
});

test("short password blocked client-side", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => json(200, info)));
  show();
  await screen.findByText(/v@x.com/);
  fill("short", "short");
  submit();
  expect(await screen.findByText("Password must be at least 12 characters")).toBeTruthy();
});

test("410 shows invalid invitation", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => json(410, { error: "gone" })));
  show();
  expect(await screen.findByText("This invitation is no longer valid")).toBeTruthy();
});

test.each([429, 500, 0])("invitation load failure %i is not reported as an invalid invitation", async (status) => {
  vi.stubGlobal("fetch", vi.fn(async () => (status ? json(status, {}) : Promise.reject(new TypeError("offline")))));
  show();
  expect(await screen.findByText("Something went wrong, please try again")).toBeTruthy();
  expect(screen.queryByText("This invitation is no longer valid")).toBeNull();
});

test("404 shows invalid invitation", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => json(404, { error: "not_found" })));
  show();
  expect(await screen.findByText("This invitation is no longer valid")).toBeTruthy();
});

test.each([
  [401, { error: "invalid_code" }, "Incorrect or expired code"],
  [422, { error: "validation", field: "password", code: "too_short" }, "Password must be at least 12 characters"],
  [422, { error: "validation", field: "password", code: "invalid" }, "This password cannot be used, please choose a shorter one"],
  [410, { error: "gone" }, "This invitation is no longer valid"],
  [500, {}, "Something went wrong, please try again"],
])("activation error %i", async (status, b, msg) => {
  vi.stubGlobal("fetch", vi.fn(async (_u: string, init?: RequestInit) => (init?.method === "POST" ? json(status, b) : json(200, info))));
  show();
  await screen.findByText(/v@x.com/);
  fill();
  submit();
  expect(await screen.findByText(msg)).toBeTruthy();
});
