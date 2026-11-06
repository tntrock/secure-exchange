import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import i18n from "../../i18n";
import Rules from "./Rules";

const MiB = 1048576;
const rules = {
  force_watermark: false, forbid_download: false, share_max_days: 30, share_default_days: 7, retention_days: 0,
  max_file_bytes: 100 * MiB, max_share_bytes: 0, upload_max_bytes: 0, quota_bytes: 0,
  domain_block: ["evil.com", "bad.org"], domain_allow: [], upload_exts: [], external_ip_allow: ["10.0.0.0/8"],
};
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status });
const mock = (put: Response) => {
  const f = vi.fn(async (_u: string, i?: RequestInit) => (i?.method === "PUT" ? put : json(200, rules)));
  vi.stubGlobal("fetch", f);
  return f;
};
const putBody = (f: ReturnType<typeof mock>) => JSON.parse(f.mock.calls.find((c) => c[1]?.method === "PUT")![1]!.body as string);
const label = (k: string) => screen.getByLabelText(i18n.t(k));

beforeEach(() => i18n.changeLanguage("en"));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

test("loads values; lists are one-per-line textareas; sizes shown in MiB", async () => {
  mock(json(200, {}));
  render(<Rules />);
  await waitFor(() => expect((label("rules.share_max_days") as HTMLInputElement).value).toBe("30"));
  expect((label("rules.domain_block") as HTMLTextAreaElement).value).toBe("evil.com\nbad.org");
  expect((label("rules.max_file_bytes") as HTMLInputElement).value).toBe("100");
});

test("saving sends edited days, MiB as bytes and list arrays, then shows affected_shares", async () => {
  const f = mock(json(200, { rules, affected_shares: 3 }));
  render(<Rules />);
  await waitFor(() => expect((label("rules.share_max_days") as HTMLInputElement).value).toBe("30"));
  fireEvent.change(label("rules.share_max_days"), { target: { value: "14" } });
  fireEvent.change(label("rules.quota_bytes"), { target: { value: "5" } });
  fireEvent.change(label("rules.domain_allow"), { target: { value: "a.com\n\n b.com " } });
  fireEvent.click(label("rules.forbid_download"));
  fireEvent.click(screen.getByRole("button", { name: i18n.t("rules.save") }));
  expect(await screen.findByText(/Affected shares: 3/)).toBeTruthy();
  const b = putBody(f);
  expect(b.share_max_days).toBe(14);
  expect(b.quota_bytes).toBe(5 * MiB);
  expect(b.max_file_bytes).toBe(100 * MiB);
  expect(b.domain_allow).toEqual(["a.com", "b.com"]);
  expect(b.external_ip_allow).toEqual(["10.0.0.0/8"]);
  expect(b.forbid_download).toBe(true);
});

test("422 shows the field error message", async () => {
  mock(json(422, { error: "validation", field: "share_max_days", code: "out_of_range" }));
  render(<Rules />);
  await waitFor(() => expect((label("rules.share_max_days") as HTMLInputElement).value).toBe("30"));
  fireEvent.click(screen.getByRole("button", { name: i18n.t("rules.save") }));
  expect(await screen.findByText(i18n.t("rules.error.share_max_days.out_of_range"))).toBeTruthy();
});
