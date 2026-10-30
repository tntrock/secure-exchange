import { afterEach, expect, test, vi } from "vitest";
import { api, ApiError, fmtDate, fmtSize } from "./api";

afterEach(() => vi.unstubAllGlobals());

const stub = (res: Response) => {
  const f = vi.fn(async (_u: string, _i?: RequestInit) => res);
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
    method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ emails: ["b@x.com"] }),
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
