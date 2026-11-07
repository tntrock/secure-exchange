import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import i18n from "../../i18n";
import Audit from "./Audit";

const row = (id: number) => ({ id, at: "2030-01-01T00:00:00Z", actor_type: "user", actor_id: "u1", actor_label: `who${id}@x.com`, ip: "1.2.3.4", user_agent: "", action: "share.create", target_type: "share", target_id: "s1", result: "ok", detail: { share_id: "s1" } });
const json = (b: unknown) => new Response(JSON.stringify(b));

const setup = (verify: unknown = { checked: 5, bad_id: 0 }) => {
  const f = vi.fn(async (u: string) => {
    if (u.startsWith("/api/admin/audit/verify")) return json(verify);
    if (u.includes("before=9")) return json({ entries: [row(5)], next_before: 0 });
    return json({ entries: [row(10)], next_before: 9 });
  });
  vi.stubGlobal("fetch", f);
  render(<MemoryRouter><Audit /></MemoryRouter>);
  return f;
};

beforeEach(() => i18n.changeLanguage("en"));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

test("filters are submitted, datetime-local becomes ISO, CSV link has no before", async () => {
  const f = setup();
  await screen.findByText("who10@x.com");
  fireEvent.change(screen.getByLabelText(i18n.t("audit.since")), { target: { value: "2030-01-02T03:04" } });
  fireEvent.change(screen.getByLabelText(i18n.t("audit.actor")), { target: { value: "bob" } });
  fireEvent.change(screen.getByLabelText(i18n.t("audit.action")), { target: { value: "share." } });
  fireEvent.click(screen.getByRole("button", { name: i18n.t("audit.filter") }));
  const since = new Date("2030-01-02T03:04").toISOString();
  const qs = new URLSearchParams({ since, actor: "bob", action: "share." }).toString();
  await waitFor(() => expect(f).toHaveBeenCalledWith(`/api/admin/audit?${qs}`, expect.anything()));
  await waitFor(() => expect(screen.getByRole("link", { name: i18n.t("audit.export") }).getAttribute("href")).toBe(`/api/admin/audit/export?${qs}`));
});

test("next passes before, previous goes back", async () => {
  const f = setup();
  await screen.findByText("who10@x.com");
  fireEvent.click(screen.getByRole("button", { name: i18n.t("audit.next") }));
  expect(await screen.findByText("who5@x.com")).toBeTruthy();
  expect(f).toHaveBeenCalledWith("/api/admin/audit?before=9", expect.anything());
  expect((screen.getByRole("button", { name: i18n.t("audit.next") }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(screen.getByRole("button", { name: i18n.t("audit.prev") }));
  expect(await screen.findByText("who10@x.com")).toBeTruthy();
});

test("verify reports intact and broken chains", async () => {
  setup();
  await screen.findByText("who10@x.com");
  fireEvent.click(screen.getByRole("button", { name: i18n.t("audit.verify") }));
  expect(await screen.findByText(i18n.t("audit.verifyOk", { n: 5 }))).toBeTruthy();
  cleanup();
  setup({ checked: 3, bad_id: 7 });
  await screen.findByText("who10@x.com");
  fireEvent.click(screen.getByRole("button", { name: i18n.t("audit.verify") }));
  expect(await screen.findByText(i18n.t("audit.verifyBad", { id: 7 }))).toBeTruthy();
});

test("shows error when list fails", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 500 })));
  render(<MemoryRouter><Audit /></MemoryRouter>);
  expect(await screen.findByRole("alert")).toBeTruthy();
});

test("object detail is rendered as JSON, not as a React child", async () => {
  setup();
  expect(await screen.findByText('{"share_id":"s1"}')).toBeTruthy();
});
