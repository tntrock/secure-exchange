import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

interface PreviewInfo { kind: string; status: string; page_count: number; width?: number; height?: number }

// The current page is the lowest-numbered page crossing the viewport middle.
export const lowestVisible = (visible: Iterable<number>): number | null => {
  let m: number | null = null;
  for (const p of visible) if (m === null || p < m) m = p;
  return m;
};

const ZMIN = 50, ZMAX = 300, ZSTEP = 25;

// Full-screen read-only viewer. `base` is the preview API prefix (staff or recipient).
export default function Viewer({ base, onClose, onSessionEnded }: { base: string; onClose: () => void; onSessionEnded?: () => void }) {
  const { t } = useTranslation();
  const [info, setInfo] = useState<PreviewInfo | null>(null);
  const [msg, setMsg] = useState("");
  const [page, setPage] = useState(1);
  const [zoom, setZoom] = useState(100);
  const closeRef = useRef<HTMLButtonElement>(null);
  const scroller = useRef<HTMLDivElement>(null);
  const videoRef = useRef<HTMLVideoElement>(null);
  const endedRef = useRef(onSessionEnded);
  endedRef.current = onSessionEnded;

  useEffect(() => { closeRef.current?.focus(); }, []);

  // map an HTTP failure to a message; 401 ends the recipient session (staff just see a re-login hint)
  const fail = useRef((status: number, code?: string) => {
    if (status === 401) { endedRef.current?.(); return setMsg(endedRef.current ? "ended" : "reLogin"); }
    if (status === 410) return setMsg("gone");
    if (status === 409) return setMsg("pending");
    if (status === 403 && (code === "view_limit" || code === "ip_denied")) return setMsg(code);
    if (status === 422 && code === "not_previewable") return setMsg("notReady");
    setMsg("error");
  }).current;

  useEffect(() => {
    let off = false;
    (async () => {
      try {
        const res = await fetch(base, { credentials: "same-origin" });
        if (off) return;
        if (!res.ok) {
          const j = await res.json().catch(() => ({}));
          return off ? undefined : fail(res.status, j.error);
        }
        const j = (await res.json()) as PreviewInfo;
        if (off) return;
        if (j.status === "pending") return setMsg("pending");
        if (j.status !== "ready") return setMsg("notReady");
        setInfo(j);
      } catch { if (!off) setMsg("error"); }
    })();
    return () => { off = true; };
  }, [base, fail]);

  const isVideo = info?.kind === "video";
  const total = isVideo ? 0 : Math.max(info?.page_count ?? 0, info ? 1 : 0);

  const go = (n: number) => {
    const p = Math.min(Math.max(n, 1), total);
    setPage(p);
    scroller.current?.querySelector(`[data-page="${p}"]`)?.scrollIntoView?.({ block: "start" });
  };
  const zoomBy = (d: number) => setZoom((z) => Math.min(ZMAX, Math.max(ZMIN, z + d)));

  // current-page indicator follows the scroll position (no IntersectionObserver in jsdom)
  useEffect(() => {
    const root = scroller.current;
    if (!total || !root || typeof IntersectionObserver === "undefined") return;
    const vis = new Set<number>();
    const io = new IntersectionObserver((es) => {
      for (const e of es) {
        const n = Number((e.target as HTMLElement).dataset.page);
        if (e.isIntersecting) vis.add(n); else vis.delete(n);
      }
      const p = lowestVisible(vis);
      if (p !== null) setPage(p);
    }, { root, rootMargin: "-50% 0px -50% 0px", threshold: 0 });
    root.querySelectorAll("[data-page]").forEach((el) => io.observe(el));
    return () => io.disconnect();
  }, [total]);

  useEffect(() => {
    if (!isVideo || !videoRef.current) return;
    const v = videoRef.current, src = `${base}/video.m3u8`;
    let hls: { destroy(): void } | undefined, off = false;
    if (v.canPlayType("application/vnd.apple.mpegurl")) { v.src = src; return; }
    void import("hls.js").then(({ default: Hls }) => {
      if (off || !Hls.isSupported()) return;
      // enableWorker off: CSP has no worker-src for blob:. Retry policy so a busy (503) segment is retried a few times.
      const retry = { maxNumRetry: 4, retryDelayMs: 1000, maxRetryDelayMs: 8000 };
      const h = new Hls({
        enableWorker: false,
        fragLoadPolicy: { default: { maxTimeToFirstByteMs: 10000, maxLoadTimeMs: 120000, timeoutRetry: retry, errorRetry: retry } },
      });
      hls = h;
      h.on(Hls.Events.ERROR, (_e: unknown, d: { fatal?: boolean; response?: { code?: number } }) => {
        if (d.fatal) fail(d.response?.code ?? 0);
      });
      h.loadSource(src);
      h.attachMedia(v);
    });
    return () => { off = true; hls?.destroy(); };
  }, [isVideo, base]);

  // a failed page image: re-check the info URL once to learn why (session ended, share gone...)
  const imgFailed = useRef(false);
  const onImgError = async () => {
    if (imgFailed.current) return;
    imgFailed.current = true;
    try {
      const res = await fetch(base, { credentials: "same-origin" });
      if (!res.ok) fail(res.status, (await res.json().catch(() => ({}))).error);
    } catch { /* leave the broken image */ }
  };

  const onKey = (e: React.KeyboardEvent) => {
    const k = e.key;
    if (k === "Escape") onClose();
    else if (isVideo || !total) return;
    else if (k === "ArrowRight" || k === "PageDown") go(page + 1);
    else if (k === "ArrowLeft" || k === "PageUp") go(page - 1);
    else if (k === "+" || k === "=") zoomBy(ZSTEP);
    else if (k === "-") zoomBy(-ZSTEP);
    else return;
    e.preventDefault();
  };

  return (
    <div role="dialog" aria-modal="true" aria-label={t("viewer.title")} tabIndex={-1} onKeyDown={onKey}
      onContextMenu={(e) => e.preventDefault()}
      style={{ position: "fixed", inset: 0, zIndex: 1000, background: "#222", color: "#eee", display: "flex", flexDirection: "column", userSelect: "none" }}>
      <div style={{ display: "flex", gap: 8, alignItems: "center", padding: 8, background: "#111" }}>
        {total > 0 && (
          <>
            <button onClick={() => go(page - 1)} disabled={page <= 1}>{t("viewer.prev")}</button>
            <span aria-live="polite">{page} / {total}</span>
            <button onClick={() => go(page + 1)} disabled={page >= total}>{t("viewer.next")}</button>
            <button onClick={() => zoomBy(-ZSTEP)} disabled={zoom <= ZMIN}>{t("viewer.zoomOut")}</button>
            <span>{zoom}%</span>
            <button onClick={() => zoomBy(ZSTEP)} disabled={zoom >= ZMAX}>{t("viewer.zoomIn")}</button>
          </>
        )}
        <span style={{ flex: 1 }} />
        <button ref={closeRef} onClick={onClose}>{t("viewer.close")}</button>
      </div>
      <div ref={scroller} style={{ flex: 1, overflow: "auto", textAlign: "center" }}>
        {msg && <p role="alert" style={{ padding: 24 }}>{t(`viewer.${msg}`)}</p>}
        {!msg && !info && <p style={{ padding: 24 }}>{t("app.loading")}</p>}
        {isVideo && (
          <video ref={videoRef} controls controlsList="nodownload" disablePictureInPicture style={{ maxWidth: "100%", maxHeight: "100%" }} />
        )}
        {total > 0 && (
          <div style={{ width: `${zoom}%`, margin: "0 auto" }}>
            {Array.from({ length: total }, (_, i) => (
              <img key={i} data-page={i + 1} src={`${base}/pages/${i + 1}`} loading="lazy" draggable={false} onError={onImgError}
                alt={t("viewer.page", { n: i + 1 })} style={{ display: "block", width: "100%", minHeight: 100, aspectRatio: info?.width && info?.height ? `${info.width} / ${info.height}` : undefined, marginBottom: 8, background: "#fff" }} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
