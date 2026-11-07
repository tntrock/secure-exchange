import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import i18n from "../i18n";
import ShareAudit from "./ShareAudit";

const e = (id: number, label: string, actor_id: string) => ({ id, at: "2030-01-01T00:00:00Z", actor_type: "recipient", actor_id, actor_label: label, ip: "1.1.1.1", user_agent: "", action: "recipient.view", target_type: "share", target_id: "s1", result: "ok", detail: "" });

beforeEach(() => i18n.changeLanguage("en"));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

test("renders label or falls back to actor id; admin uses admin URL", async () => {
  const f = vi.fn(async () => new Response(JSON.stringify({ entries: [e(1, "a@x.com", "r1"), e(2, "", "r2")] })));
  vi.stubGlobal("fetch", f);
  render(<ShareAudit id="s1" admin />);
  expect(await screen.findByText("a@x.com")).toBeTruthy();
  expect(screen.getByText("r2")).toBeTruthy();
  expect(f).toHaveBeenCalledWith("/api/admin/shares/s1/audit", expect.anything());
});

test("owner URL, empty and error states", async () => {
  const f = vi.fn(async () => new Response(JSON.stringify({ entries: [] })));
  vi.stubGlobal("fetch", f);
  render(<ShareAudit id="s1" admin={false} />);
  expect(await screen.findByText(i18n.t("audit.empty"))).toBeTruthy();
  expect(f).toHaveBeenCalledWith("/api/shares/s1/audit", expect.anything());
  cleanup();
  vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 500 })));
  render(<ShareAudit id="s1" admin={false} />);
  expect(await screen.findByRole("alert")).toBeTruthy();
});
