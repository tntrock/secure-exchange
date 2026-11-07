import { useEffect, useRef } from "react";

const FOCUSABLE = 'a[href],button:not([disabled]),input:not([disabled]):not([type="hidden"]),select:not([disabled]),textarea:not([disabled]),video[controls],[tabindex]:not([tabindex="-1"])';

// Modal behaviour: focus in on mount, Tab wraps inside `ref`, Esc closes, focus restored on unmount.
export function useModal(ref: React.RefObject<HTMLElement | null>, onClose: () => void): void {
  const close = useRef(onClose);
  close.current = onClose;
  useEffect(() => {
    const root = ref.current;
    if (!root) return;
    const opener = document.activeElement as HTMLElement | null;
    const items = () => Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE));
    const first = items()[0];
    if (first) first.focus();
    else { root.tabIndex = -1; root.focus(); }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { close.current(); return; }
      if (e.key !== "Tab") return;
      const list = items();
      if (!list.length) { e.preventDefault(); root.focus(); return; }
      const a = document.activeElement;
      const i = list.indexOf(a as HTMLElement);
      if (!root.contains(a) || (e.shiftKey && (i <= 0)) || (!e.shiftKey && i === list.length - 1)) {
        e.preventDefault();
        list[e.shiftKey && root.contains(a) ? list.length - 1 : 0].focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      if (opener && document.contains(opener)) opener.focus();
    };
  }, [ref]);
}
