import { afterEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import i18n from "../i18n";
import ShareDetail from "./ShareDetail";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const detail = {
  id: "s1", message: "", allow_download: false, watermark: true, expires_at: "2030-01-01T00:00:00Z", max_views: null,
  view_count: 0, ip_allow: [], revoked: false, expired: false, created_at: "2029-01-01T00:00:00Z",
  files: [{ id: "f1", name: "a.pdf", size: 1, deleted: false }],
  recipients: [
    { id: "r1", email: "gone@x.com", revoked: true, first_opened_at: null, last_access_at: null },
    { id: "r2", email: "ok@x.com", revoked: false, first_opened_at: null, last_access_at: null },
  ],
};

test("revoked recipient has no revoke button; revoking another calls the right URL", async () => {
  const f = vi.fn((_url: string, init?: RequestInit) =>
    Promise.resolve(init?.method === "POST" ? new Response(null, { status: 204 }) : new Response(JSON.stringify(detail))),
  );
  vi.stubGlobal("fetch", f);
  vi.stubGlobal("confirm", () => true);
  render(
    <MemoryRouter initialEntries={["/shares/s1"]}>
      <Routes><Route path="/shares/:id" element={<ShareDetail />} /></Routes>
    </MemoryRouter>,
  );
  await screen.findByText("ok@x.com");
  const btns = screen.getAllByRole("button", { name: i18n.t("share.revoke") });
  expect(btns).toHaveLength(1);
  fireEvent.click(btns[0]);
  await waitFor(() => expect(f).toHaveBeenCalledWith("/api/shares/s1/recipients/r2/revoke", expect.objectContaining({ method: "POST" })));
});

test("adding recipients to an expired share shows the expired message", async () => {
  const f = vi.fn((_url: string, init?: RequestInit) =>
    Promise.resolve(
      init?.method === "POST" ? new Response(JSON.stringify({ error: "expired" }), { status: 409 }) : new Response(JSON.stringify(detail)),
    ),
  );
  vi.stubGlobal("fetch", f);
  render(
    <MemoryRouter initialEntries={["/shares/s1"]}>
      <Routes><Route path="/shares/:id" element={<ShareDetail />} /></Routes>
    </MemoryRouter>,
  );
  await screen.findByText("ok@x.com");
  fireEvent.change(screen.getByLabelText(i18n.t("share.addRecipients")), { target: { value: "new@x.com" } });
  fireEvent.click(screen.getByRole("button", { name: i18n.t("share.add") }));
  expect((await screen.findByRole("alert")).textContent).toBe(i18n.t("share.error.expired"));
  expect(i18n.exists("share.error.expired")).toBe(true);
});

test("revoking the whole share needs confirmation and refreshes to Revoked", async () => {
  let revoked = false;
  const f = vi.fn((_url: string, init?: RequestInit) => {
    if (init?.method === "POST") { revoked = true; return Promise.resolve(new Response(null, { status: 204 })); }
    return Promise.resolve(new Response(JSON.stringify({ ...detail, revoked, message: "hi", ip_allow: ["10.0.0.0/8"], max_views: 5 })));
  });
  vi.stubGlobal("fetch", f);
  const confirm = vi.fn(() => false);
  vi.stubGlobal("confirm", confirm);
  render(
    <MemoryRouter initialEntries={["/shares/s1"]}>
      <Routes><Route path="/shares/:id" element={<ShareDetail />} /></Routes>
    </MemoryRouter>,
  );
  const btn = await screen.findByRole("button", { name: i18n.t("share.revokeShare") });
  expect(screen.getByText(`${i18n.t("share.ipAllow")}: 10.0.0.0/8`)).toBeTruthy();
  expect(screen.getByText(`${i18n.t("share.views")}: 0 / 5`)).toBeTruthy();
  fireEvent.click(btn);
  expect(confirm).toHaveBeenCalledWith(i18n.t("share.confirmRevoke"));
  expect(f.mock.calls.some(([, i]) => i?.method === "POST")).toBe(false);
  confirm.mockReturnValue(true);
  fireEvent.click(btn);
  await waitFor(() => expect(screen.queryByRole("button", { name: i18n.t("share.revokeShare") })).toBeNull());
  expect(f).toHaveBeenCalledWith("/api/shares/s1/revoke", expect.objectContaining({ method: "POST" }));
  expect(screen.getByText(`${i18n.t("share.statusLabel")}: ${i18n.t("share.status.revoked")}`)).toBeTruthy();
});

test("status column uses the status label", async () => {
  vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(new Response(JSON.stringify(detail)))));
  render(
    <MemoryRouter initialEntries={["/shares/s1"]}>
      <Routes><Route path="/shares/:id" element={<ShareDetail />} /></Routes>
    </MemoryRouter>,
  );
  await screen.findByText("ok@x.com");
  expect(i18n.exists("share.statusLabel")).toBe(true);
  expect(screen.getByRole("columnheader", { name: i18n.t("share.statusLabel") })).toBeTruthy();
});
