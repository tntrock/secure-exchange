import { afterEach, expect, test } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import "../i18n";
import Login from "./Login";

afterEach(cleanup);

test("login page has a language switcher that changes visible text", async () => {
  render(<MemoryRouter><Login /></MemoryRouter>);
  const sel = screen.getByRole("combobox") as HTMLSelectElement;
  fireEvent.change(sel, { target: { value: "zh-TW" } });
  expect(await screen.findByRole("heading", { name: "登入" })).toBeTruthy();
  fireEvent.change(sel, { target: { value: "en" } });
  expect(await screen.findByRole("heading", { name: "Log in" })).toBeTruthy();
});
