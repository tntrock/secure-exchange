import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import i18n from "../i18n";

const toDataURL = vi.hoisted(() => vi.fn(async () => "data:image/png;base64,QR"));
vi.mock("qrcode", () => ({ default: { toDataURL } }));

import TotpSetup from "./TotpSetup";

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status });
function mockApi(setup: Response, enable: Response) {
  const f = vi.fn(async (url: string) => (url.endsWith("/setup") ? setup : enable));
  vi.stubGlobal("fetch", f);
  return f;
}

beforeEach(() => i18n.changeLanguage("en"));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.clearAllMocks(); });

test("setup renders the QR of the otpauth url, enabling with a code succeeds", async () => {
  const f = mockApi(json(200, { otpauth_url: "otpauth://totp/x" }), new Response(null, { status: 204 }));
  render(<TotpSetup />);
  fireEvent.click(screen.getByRole("button", { name: "Start setup" }));
  const img = await screen.findByRole("img", { name: "Two-factor authentication QR code" });
  expect(img.getAttribute("src")).toBe("data:image/png;base64,QR");
  expect(toDataURL).toHaveBeenCalledWith("otpauth://totp/x", { margin: 1, width: 220 });
  fireEvent.change(screen.getByLabelText("Code"), { target: { value: "123456" } });
  fireEvent.click(screen.getByRole("button", { name: "Enable" }));
  expect(await screen.findByText("Two-factor authentication is enabled")).toBeTruthy();
  expect(f).toHaveBeenLastCalledWith("/api/me/totp/enable", expect.objectContaining({ method: "POST", body: JSON.stringify({ code: "123456" }) }));
});

test("setup failure shows the error and keeps the start button", async () => {
  mockApi(json(500, {}), json(500, {}));
  render(<TotpSetup />);
  fireEvent.click(screen.getByRole("button", { name: "Start setup" }));
  expect((await screen.findByRole("alert")).textContent).toBe("Invalid code or setup failed");
  expect(screen.getByRole("button", { name: "Start setup" })).toBeTruthy();
});

test("wrong code shows the error and stays on the form", async () => {
  mockApi(json(200, { otpauth_url: "otpauth://totp/x" }), json(400, { error: "invalid_code" }));
  render(<TotpSetup />);
  fireEvent.click(screen.getByRole("button", { name: "Start setup" }));
  fireEvent.change(await screen.findByLabelText("Code"), { target: { value: "000000" } });
  fireEvent.click(screen.getByRole("button", { name: "Enable" }));
  expect((await screen.findByRole("alert")).textContent).toBe("Invalid code or setup failed");
  expect(screen.queryByText("Two-factor authentication is enabled")).toBeNull();
});
