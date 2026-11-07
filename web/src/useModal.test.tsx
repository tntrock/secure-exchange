import { useRef, useState } from "react";
import { afterEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { useModal } from "./useModal";

afterEach(cleanup);

function Box({ onClose }: { onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  useModal(ref, onClose);
  return <div ref={ref}><button>first</button><button disabled>skip</button><button>last</button></div>;
}
function Host({ onClose = () => {} }: { onClose?: () => void }) {
  const [open, setOpen] = useState(false);
  return <><button onClick={() => setOpen(true)}>opener</button>{open && <Box onClose={() => { onClose(); setOpen(false); }} />}</>;
}
const open = () => { const b = screen.getByText("opener"); b.focus(); fireEvent.click(b); return b; };

test("focus moves to the first control inside", () => {
  render(<Host />);
  open();
  expect(document.activeElement).toBe(screen.getByText("first"));
});

test("Tab wraps from last to first, Shift+Tab from first to last", () => {
  render(<Host />);
  open();
  screen.getByText("last").focus();
  fireEvent.keyDown(document.activeElement!, { key: "Tab" });
  expect(document.activeElement).toBe(screen.getByText("first"));
  fireEvent.keyDown(document.activeElement!, { key: "Tab", shiftKey: true });
  expect(document.activeElement).toBe(screen.getByText("last"));
});

test("Tab with focus outside is pulled back in", () => {
  render(<Host />);
  open();
  (document.activeElement as HTMLElement).blur();
  fireEvent.keyDown(document.body, { key: "Tab" });
  expect(document.activeElement).toBe(screen.getByText("first"));
});

test("Escape calls onClose; unmount restores focus to the opener", () => {
  const onClose = vi.fn();
  render(<Host onClose={onClose} />);
  const opener = open();
  fireEvent.keyDown(document.body, { key: "Escape" });
  expect(onClose).toHaveBeenCalledTimes(1);
  expect(screen.queryByText("first")).toBeNull();
  expect(document.activeElement).toBe(opener);
});

test("with nothing focusable the container itself takes focus", () => {
  function Empty() { const r = useRef<HTMLDivElement>(null); useModal(r, () => {}); return <div ref={r} data-testid="e" />; }
  render(<Empty />);
  expect(document.activeElement).toBe(screen.getByTestId("e"));
  fireEvent.keyDown(document.body, { key: "Tab" });
  expect(document.activeElement).toBe(screen.getByTestId("e"));
});

test("Escape during IME composition or already handled does not close", () => {
  const onClose = vi.fn();
  render(<Host onClose={onClose} />);
  open();
  fireEvent.keyDown(document.body, { key: "Escape", isComposing: true });
  expect(onClose).not.toHaveBeenCalled();
  const e = new KeyboardEvent("keydown", { key: "Escape", cancelable: true, bubbles: true });
  e.preventDefault();
  document.body.dispatchEvent(e);
  expect(onClose).not.toHaveBeenCalled();
});
