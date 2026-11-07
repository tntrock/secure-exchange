import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import i18n from "../../i18n";
import AllShares from "./AllShares";

const json = (body: unknown) => new Response(JSON.stringify(body));
const share = (i: number) => ({
  id: `s${i}`, created_at: "2030-01-01T00:00:00Z", expires_at: "2030-01-08T00:00:00Z", revoked: false, expired: false,
  file_count: 1, recipient_count: 2, view_count: 0, max_views: null, owner_email: `owner${i}@x.com`,
});
const req = { id: "q1", created_at: "2030-01-01T00:00:00Z", expires_at: "2030-01-08T00:00:00Z", revoked: false, expired: false,
  file_count: 0, total_bytes: 0, max_files: 10, max_total_bytes: 1, uploader_count: 1, owner_email: "reqowner@x.com" };

const setup = (page: unknown[] = [share(1)]) => {
  const f = vi.fn(async (u: string) => json(u.startsWith("/api/admin/requests") ? [req] : page));
  vi.stubGlobal("fetch", f);
  render(<MemoryRouter><AllShares /></MemoryRouter>);
  return f;
};

beforeEach(() => i18n.changeLanguage("en"));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

test("lists shares with owner email", async () => {
  const f = setup();
  expect(await screen.findByText("owner1@x.com")).toBeTruthy();
  expect(f).toHaveBeenCalledWith("/api/admin/shares?q=&offset=0", expect.anything());
});

test("search refetches with q", async () => {
  const f = setup();
  await screen.findByText("owner1@x.com");
  fireEvent.change(screen.getByRole("searchbox"), { target: { value: "bob" } });
  fireEvent.submit(screen.getByRole("search"));
  await waitFor(() => expect(f).toHaveBeenCalledWith("/api/admin/shares?q=bob&offset=0", expect.anything()));
});

test("more requests offset=100 and appends", async () => {
  const full = Array.from({ length: 100 }, (_, i) => share(i));
  const f = setup(full);
  await screen.findByText("owner0@x.com");
  fireEvent.click(screen.getByRole("button", { name: i18n.t("allShares.more") }));
  await waitFor(() => expect(f).toHaveBeenCalledWith("/api/admin/shares?q=&offset=100", expect.anything()));
});

test("requests tab lists requests", async () => {
  const f = setup();
  await screen.findByText("owner1@x.com");
  fireEvent.click(screen.getByRole("button", { name: i18n.t("allShares.tabRequests") }));
  expect(await screen.findByText("reqowner@x.com")).toBeTruthy();
  expect(f).toHaveBeenCalledWith("/api/admin/requests?q=&offset=0", expect.anything());
});
