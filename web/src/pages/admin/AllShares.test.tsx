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

const deferred = () => { let res!: (r: Response) => void; const p = new Promise<Response>((r) => { res = r; }); return { p, res }; };

test("stale response from an earlier filter does not overwrite the latest", async () => {
  const d: Record<string, ReturnType<typeof deferred>> = { "": deferred(), a: deferred(), b: deferred() };
  vi.stubGlobal("fetch", vi.fn((u: string) => d[new URL(u, "http://x").searchParams.get("q")!].p));
  render(<MemoryRouter><AllShares /></MemoryRouter>);
  for (const v of ["a", "b"]) {
    fireEvent.change(screen.getByRole("searchbox"), { target: { value: v } });
    fireEvent.submit(screen.getByRole("search"));
  }
  d.b.res(json([share(2)]));
  expect(await screen.findByText("owner2@x.com")).toBeTruthy();
  d[""].res(json([share(0)])); d.a.res(json([share(1)]));
  await new Promise((r) => setTimeout(r, 20));
  expect(screen.getByText("owner2@x.com")).toBeTruthy();
  expect(screen.queryByText("owner1@x.com")).toBeNull();
  expect(screen.queryByText("owner0@x.com")).toBeNull();
});

test("load more resolving after a filter change does not append", async () => {
  const full = Array.from({ length: 100 }, (_, i) => share(i));
  const more = deferred();
  const f = vi.fn((u: string) => {
    if (u.includes("offset=100")) return more.p;
    return Promise.resolve(json(u.includes("q=bob") ? [share(900)] : full));
  });
  vi.stubGlobal("fetch", f);
  render(<MemoryRouter><AllShares /></MemoryRouter>);
  await screen.findByText("owner0@x.com");
  fireEvent.click(screen.getByRole("button", { name: i18n.t("allShares.more") }));
  fireEvent.change(screen.getByRole("searchbox"), { target: { value: "bob" } });
  fireEvent.submit(screen.getByRole("search"));
  await screen.findByText("owner900@x.com");
  more.res(json([share(901)]));
  await new Promise((r) => setTimeout(r, 20));
  expect(screen.queryByText("owner901@x.com")).toBeNull();
  expect(screen.getByText("owner900@x.com")).toBeTruthy();
});
