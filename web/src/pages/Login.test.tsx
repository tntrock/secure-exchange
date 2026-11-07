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
  expect(f).toHaveBeenCalledWith("/api/auth/totp", expect.objectContaining({ body: JSON.stringify({ code: "123456" }) }));
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

test("vendor goes to /vendor/shares", async () => {
  vi.stubGlobal("fetch", vi.fn(async (url: string) => (url.endsWith("/login") ? json(200, { mfa_required: false }) : json(200, { role: "vendor" }))));
  void i18n.changeLanguage("en");
  render(
    <MemoryRouter initialEntries={["/login"]}>
      <Routes><Route path="/login" element={<Login />} /><Route path="/vendor/shares" element={<p>vendor home</p>} /></Routes>
    </MemoryRouter>,
  );
  fireEvent.change(screen.getByLabelText("Email"), { target: { value: "v@x.com" } });
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: "Log in" }));
  expect(await screen.findByText("vendor home")).toBeTruthy();
});

test("403 ip_denied shows the network-location message", async () => {
  setup(json(403, { error: "ip_denied" }));
  expect(await screen.findByText(i18n.t("recipient.error.ipDenied"))).toBeTruthy();
});

vi.mock("qrcode", () => ({ default: { toDataURL: vi.fn(async () => "data:image/png;base64,xx") } }));

function setupEnroll(enroll: Response) {
  const f = vi.fn(async (url: string) => (url.endsWith("/login") ? json(200, { mfa_required: false, totp_setup_required: true }) : url.endsWith("/totp/setup") ? json(200, { otpauth_url: "otpauth://x" }) : url.endsWith("/totp/enroll") ? enroll : json(200, { role: "staff" })));
  vi.stubGlobal("fetch", f);
  void i18n.changeLanguage("en");
  render(<MemoryRouter initialEntries={["/login"]}><Routes><Route path="/login" element={<Login />} /><Route path="/files" element={<p>files page</p>} /></Routes></MemoryRouter>);
  fireEvent.change(screen.getByLabelText("Email"), { target: { value: "a@x.com" } });
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: "pw" } });
  fireEvent.click(screen.getByRole("button", { name: "Log in" }));
  return f;
}

test("forced enrolment shows the QR, wrong code errors, right code navigates", async () => {
  const f = setupEnroll(json(401, { error: "invalid_code" }));
  expect(await screen.findByRole("img")).toBeTruthy();
  fireEvent.change(screen.getByLabelText("Code (6 digits)"), { target: { value: "000000" } });
  fireEvent.click(screen.getByRole("button", { name: "Verify" }));
  expect((await screen.findByRole("alert")).textContent).toBe("Invalid code");
  expect(f).toHaveBeenCalledWith("/api/auth/totp/enroll", expect.objectContaining({ body: JSON.stringify({ code: "000000" }) }));
  cleanup();
  setupEnroll(json(200, { mfa_required: false }));
  await screen.findByRole("img");
  fireEvent.change(screen.getByLabelText("Code (6 digits)"), { target: { value: "123456" } });
  fireEvent.click(screen.getByRole("button", { name: "Verify" }));
  expect(await screen.findByText("files page")).toBeTruthy();
});

function setupLdap(ldap: Response | "off" | "fail") {
  const f = vi.fn(async (url: string) => {
    if (url.endsWith("/methods")) { if (ldap === "fail") throw new TypeError("offline"); return json(200, { ldap: ldap !== "off" }); }
    if (url.endsWith("/ldap")) return ldap as Response;
    return json(200, { role: "staff" });
  });
  vi.stubGlobal("fetch", f);
  void i18n.changeLanguage("zh-TW");
  render(<MemoryRouter initialEntries={["/login"]}><Routes><Route path="/login" element={<Login />} /><Route path="/files" element={<p>files page</p>} /></Routes></MemoryRouter>);
  return f;
}

async function submitLdap() {
  fireEvent.change(await screen.findByLabelText("帳號"), { target: { value: "alice" } });
  const pw = screen.getAllByLabelText("密碼")[1];
  fireEvent.change(pw, { target: { value: "pw" } });
  fireEvent.click(screen.getAllByRole("button", { name: "登入" })[1]);
}

test("ldap on: domain form posts to /api/auth/ldap and navigates to files", async () => {
  const f = setupLdap(json(200, { mfa_required: false, totp_setup_required: false }));
  expect(await screen.findByRole("heading", { name: "網域帳號" })).toBeTruthy();
  expect((await screen.findByLabelText("帳號") as HTMLInputElement).autocomplete).toBe("username");
  await submitLdap();
  expect(await screen.findByText("files page")).toBeTruthy();
  expect(f).toHaveBeenCalledWith("/api/auth/ldap", expect.objectContaining({ body: JSON.stringify({ username: "alice", password: "pw" }) }));
});

test.each(["off", "fail"] as const)("ldap %s: only the local form shows", async (mode) => {
  const f = setupLdap(mode);
  await screen.findByLabelText("電子郵件");
  await vi.waitFor(() => expect(f).toHaveBeenCalledWith("/api/auth/methods", expect.anything()));
  await new Promise((r) => setTimeout(r, 0));
  expect(screen.queryByRole("heading", { name: "網域帳號" })).toBeNull();
});

test.each([
  [503, "網域伺服器暫時無法連線，請稍後再試或改用本機帳號"],
  [409, "這個網域帳號的 email 已被另一個網域帳號使用，請聯絡管理員"],
  [401, "帳號或密碼錯誤"],
  [429, "嘗試次數過多，請稍後再試"],
])("ldap failure %i shows its message", async (status, msg) => {
  setupLdap(json(status, { error: "x" }));
  await submitLdap();
  expect((await screen.findByRole("alert")).textContent).toBe(msg);
});
