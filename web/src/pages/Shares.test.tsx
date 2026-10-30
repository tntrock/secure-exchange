import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import i18n from "../i18n";
import Shares from "./Shares";

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status });
const row = (id: string, o: object) => ({
  id, created_at: "2030-01-01T00:00:00Z", expires_at: "2030-02-01T00:00:00Z", revoked: false, expired: false,
  file_count: 2, recipient_count: 3, view_count: 4, max_views: null, ...o,
});
const renderPage = (res: Response) => {
  vi.stubGlobal("fetch", vi.fn(async () => res));
  render(<MemoryRouter><Shares /></MemoryRouter>);
};

beforeEach(() => i18n.changeLanguage("en"));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

test("empty list shows the empty message", async () => {
  renderPage(json(200, null));
  expect(await screen.findByText("No shares yet")).toBeTruthy();
});

test("load failure shows the generic error", async () => {
  renderPage(json(500, {}));
  expect((await screen.findByRole("alert")).textContent).toBe("Something went wrong, please try again");
});

test("rows show status, counts, views and link to the detail page", async () => {
  renderPage(json(200, [row("s1", {}), row("s2", { expired: true, max_views: 10 }), row("s3", { revoked: true, expired: true })]));
  const links = await screen.findAllByRole("link");
  expect(links.map((l) => l.getAttribute("href"))).toEqual(["/shares/s1", "/shares/s2", "/shares/s3"]);
  const cells = (i: number) => [...screen.getAllByRole("row")[i].querySelectorAll("td")].slice(2).map((td) => td.textContent);
  expect(cells(1)).toEqual(["Active", "2", "3", "4"]);
  expect(cells(2)).toEqual(["Expired", "2", "3", "4 / 10"]);
  expect(cells(3)).toEqual(["Revoked", "2", "3", "4"]);
});
