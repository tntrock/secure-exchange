import { afterEach, expect, test, vi } from "vitest";
import { api, ApiError, fmtDate, fmtSize } from "./api";

afterEach(() => vi.unstubAllGlobals());

const stub = (res: Response) => {
  const f = vi.fn(async (_u: string, _i?: RequestInit) => res.clone());
  vi.stubGlobal("fetch", f);
  return f;
};

test("GET sends no body or content type and returns the JSON", async () => {
  const me = { id: "u1", email: "a@x.com", display_name: "A", role: "staff", totp_enabled: false };
  const f = stub(new Response(JSON.stringify(me)));
  expect(await api.me()).toEqual(me);
  expect(f).toHaveBeenCalledWith("/api/me", { method: "GET", credentials: "same-origin", headers: undefined, body: undefined });
});

test("204 resolves to undefined", async () => {
  const f = stub(new Response(null, { status: 204 }));
  expect(await api.logout()).toBeUndefined();
  expect(f.mock.calls[0][0]).toBe("/api/auth/logout");
  expect(f.mock.calls[0][1]?.method).toBe("POST");
});

test("JSON bodies are sent with a content type", async () => {
  const f = stub(new Response(JSON.stringify([])));
  await api.addRecipients("s1", ["b@x.com"]);
  expect(f).toHaveBeenCalledWith("/api/shares/s1/recipients", {
    method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ emails: ["b@x.com"], vendor_ids: [] }),
  });
});

test("errors become ApiError with status, field and code", async () => {
  stub(new Response(JSON.stringify({ error: "validation", field: "emails", code: "invalid" }), { status: 422 }));
  const e = await api.createShare({ file_ids: [], emails: [], allow_download: false, watermark: true, expires_at: "", max_views: null, ip_allow: [], message: "" }).catch((x) => x);
  expect(e).toBeInstanceOf(ApiError);
  expect([e.status, e.message, e.field, e.code]).toEqual([422, "validation", "emails", "invalid"]);
});

test("a non-JSON error body still yields an ApiError", async () => {
  stub(new Response("bad gateway", { status: 502 }));
  const e = await api.revokeShare("s1").catch((x) => x);
  expect(e).toBeInstanceOf(ApiError);
  expect([e.status, e.message, e.field]).toEqual([502, "error", undefined]);
});

test("recipient URLs escape the token", async () => {
  const f = stub(new Response(null, { status: 204 }));
  await api.recipientLogout("a/b c");
  expect(f.mock.calls[0][0]).toBe("/api/s/a%2Fb%20c/logout");
});

test("fmtSize scales units and caps at TB", () => {
  expect(fmtSize(0, "en")).toBe("0 B");
  expect(fmtSize(1023, "en")).toBe("1,023 B");
  expect(fmtSize(1536, "en")).toBe("1.5 KB");
  expect(fmtSize(5 * 1024 ** 3, "en")).toBe("5 GB");
  expect(fmtSize(2048 * 1024 ** 4, "en")).toBe("2,048 TB");
});

test("fmtDate formats in the given language", () => {
  const s = "2030-01-02T03:04:00Z";
  expect(fmtDate(s, "en")).toBe(new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short" }).format(new Date(s)));
  expect(fmtDate(s, "en")).toContain("2030");
});

test("audit helpers build URLs and skip empty filters", async () => {
  const f = stub(new Response(JSON.stringify({ entries: [], next_before: 0 })));
  await api.auditList({ actor: "a b", action: "", before: 5 });
  expect(f.mock.calls[0][0]).toBe("/api/admin/audit?actor=a+b&before=5");
  await api.auditList({});
  expect(f.mock.calls[1][0]).toBe("/api/admin/audit");
  expect(api.auditExportURL({ action: "share.", before: 5 })).toBe("/api/admin/audit/export?action=share.");
  expect(api.auditExportURL({})).toBe("/api/admin/audit/export");
});

test("audit, share audit and notification endpoints", async () => {
  const f = stub(new Response(JSON.stringify({})));
  await api.auditVerify();
  await api.auditForwarding();
  await api.shareAudit("s/1", true);
  await api.shareAudit("s1", false);
  await api.getNotifyPrefs();
  expect(f.mock.calls.map((c) => `${c[1]?.method} ${c[0]}`)).toEqual([
    "POST /api/admin/audit/verify", "GET /api/admin/audit/forwarding", "GET /api/admin/shares/s%2F1/audit", "GET /api/shares/s1/audit", "GET /api/me/notifications",
  ]);
  const g = stub(new Response(null, { status: 204 }));
  await api.putNotifyPrefs({ first_open: true, download: false, upload: true });
  expect(g.mock.calls[0][1]?.method).toBe("PUT");
});

test("headFile maps status to a code; 403 fetches the reason with one GET", async () => {
  const { headFile } = await import("./api");
  const f = vi.fn(async (_u: string, init?: RequestInit) => {
    if (init?.method === "HEAD") return new Response(null, { status: 403 });
    return new Response(JSON.stringify({ error: "view_only" }), { status: 403 });
  });
  vi.stubGlobal("fetch", f);
  await expect(headFile("/x")).rejects.toMatchObject({ status: 403, message: "view_only" });
  expect(f).toHaveBeenCalledTimes(2);
  for (const [s, c] of [[409, "scan_pending"], [423, "scan_pending"], [429, "rate_limited"], [500, "error"]] as const) {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: s })));
    await expect(headFile("/x")).rejects.toMatchObject({ status: s, message: c });
  }
  vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 403 })));
  await expect(headFile("/x")).rejects.toMatchObject({ message: "forbidden" }); // GET gave no JSON
  vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 200 })));
  await expect(headFile("/x")).resolves.toBeUndefined();
});
