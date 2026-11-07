import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import "../i18n";
import TotpQr from "./TotpQr";

afterEach(cleanup);

vi.mock("qrcode", () => ({ default: { toDataURL: vi.fn(async () => "data:image/png;base64,QR") } }));

test("shows the QR and the secret in groups of four", async () => {
  render(<TotpQr url="otpauth://totp/SX:a%40x.com?secret=JBSWY3DPEHPK3PXPAB&issuer=SX" />);
  expect((await screen.findByRole("img")).getAttribute("src")).toBe("data:image/png;base64,QR");
  expect(screen.getByText("JBSW Y3DP EHPK 3PXP AB")).toBeTruthy();
});

test("no secret line when the url has none", async () => {
  render(<TotpQr url="otpauth://x" />);
  await screen.findByRole("img");
  expect(document.querySelector("code")).toBeNull();
});
