import { afterEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import i18n from "../i18n";
import Login from "./Login";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

test("login page has a language switcher that changes visible text", async () => {
  render(<MemoryRouter><Login /></MemoryRouter>);
  const sel = screen.getByRole("combobox") as HTMLSelectElement;
  fireEvent.change(sel, { target: { value: "zh-TW" } });
  expect(await screen.findByRole("heading", { name: "登入" })).toBeTruthy();
  fireEvent.change(sel, { target: { value: "en" } });
  expect(await screen.findByRole("heading", { name: "Log in" })).toBeTruthy();
});

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status });

// login and totp answer with the given responses; returns the fetch mock
function setup(login: Response, totp: Response = new Response(null, { status: 204 })) {
  const f = vi.fn(async (url: string) => (url.endsWith("/login") ? login : totp));
  vi.stubGlobal("fetch", f);
  void i18n.changeLanguage("en");
  render(
    <MemoryRouter initialEntries={["/login"]}>
      <Routes><Route path="/login" element={<Login />} /><Route path="/files" element={<p>files page</p>} /></Routes>
    </MemoryRouter>,
  );
  fireEvent.change(screen.getByLabelText("Email"), { target: { value: "a@x.com" } });
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: "Log in" }));
  return f;
}

test("password-only login navigates to files", async () => {
  const f = setup(json(200, { mfa_required: false }));
  expect(await screen.findByText("files page")).toBeTruthy();
  expect(f).toHaveBeenCalledWith("/api/auth/login", expect.objectContaining({ body: JSON.stringify({ email: "a@x.com", password: "pw" }) }));
});

test("mfa login asks for the code, then navigates", async () => {
  const f = setup(json(200, { mfa_required: true }));
  expect(await screen.findByRole("heading", { name: "Two-factor authentication" })).toBeTruthy();
  fireEvent.change(screen.getByLabelText("Code (6 digits)"), { target: { value: "123456" } });
  fireEvent.click(screen.getByRole("button", { name: "Verify" }));
  expect(await screen.findByText("files page")).toBeTruthy();
  expect(f).toHaveBeenLastCalledWith("/api/auth/totp", expect.objectContaining({ body: JSON.stringify({ code: "123456" }) }));
});

test("wrong mfa code shows invalid code", async () => {
  setup(json(200, { mfa_required: true }), json(401, { error: "invalid" }));
  fireEvent.change(await screen.findByLabelText("Code (6 digits)"), { target: { value: "000000" } });
  fireEvent.click(screen.getByRole("button", { name: "Verify" }));
  expect((await screen.findByRole("alert")).textContent).toBe("Invalid code");
});

test.each([
  [401, "Invalid email or password"],
  [429, "Too many attempts, try again later"],
  [500, "Something went wrong, please try again"],
])("login failure %i shows its message", async (status, msg) => {
  setup(json(status, { error: "x" }));
  expect((await screen.findByRole("alert")).textContent).toBe(msg);
  expect(screen.queryByText("files page")).toBeNull();
});

test("network failure shows the generic error", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("offline"); }));
  void i18n.changeLanguage("en");
  render(<MemoryRouter><Login /></MemoryRouter>);
  fireEvent.change(screen.getByLabelText("Email"), { target: { value: "a@x.com" } });
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: "Log in" }));
  expect((await screen.findByRole("alert")).textContent).toBe("Something went wrong, please try again");
});
