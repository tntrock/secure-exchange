import { afterEach, expect, test, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import Private from "./Private";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
const me = (role: string) => vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ role }))));
const show = (at: string) => render(
  <MemoryRouter initialEntries={[at]}>
    <Routes>
      <Route path="/files" element={<Private roles={["staff", "admin"]}><p>staff page</p></Private>} />
      <Route path="/vendor/shares" element={<Private roles={["vendor"]}><p>vendor page</p></Private>} />
      <Route path="/login" element={<p>login page</p>} />
    </Routes>
  </MemoryRouter>,
);

test("vendor visiting /files is redirected", async () => {
  me("vendor");
  show("/files");
  expect(await screen.findByText("vendor page")).toBeTruthy();
});

test("staff visiting /vendor/shares is redirected", async () => {
  me("staff");
  show("/vendor/shares");
  expect(await screen.findByText("staff page")).toBeTruthy();
});

test("matching role renders; 401 goes to login", async () => {
  me("admin");
  show("/files");
  expect(await screen.findByText("staff page")).toBeTruthy();
  cleanup();
  vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 401 })));
  show("/files");
  expect(await screen.findByText("login page")).toBeTruthy();
});

test("login redirect carries the visited path as state.from", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 401 })));
  const Login = () => <p>from {String((useLocation().state as { from?: string } | null)?.from)}</p>;
  render(
    <MemoryRouter initialEntries={["/files/x"]}>
      <Routes>
        <Route path="/files/x" element={<Private roles={["staff"]}><p>x</p></Private>} />
        <Route path="/login" element={<Login />} />
      </Routes>
    </MemoryRouter>,
  );
  expect(await screen.findByText("from /files/x")).toBeTruthy();
});
