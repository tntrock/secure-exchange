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
