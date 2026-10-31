import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api, fmtDate, type TraceResult } from "../../api";

export default function Trace() {
  const { t, i18n } = useTranslation();
  const [code, setCode] = useState("");
  const [sha, setSha] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [res, setRes] = useState<TraceResult | null>(null);
  const [err, setErr] = useState(false);
  const [busy, setBusy] = useState(false);

  const run = async (q: { code: string } | { sha256: string } | File) => {
    setBusy(true);
    setErr(false);
    try { setRes(await api.trace(q)); } catch { setRes(null); setErr(true); } finally { setBusy(false); }
  };
  const go = (ev: React.FormEvent, q: { code: string } | { sha256: string } | File | null) => {
    ev.preventDefault();
    if (q) void run(q);
  };

  return (
    <>
      <h1>{t("trace.title")}</h1>
      <p>{t("trace.intro")}</p>
      <form onSubmit={(e) => go(e, code.trim() ? { code: code.trim() } : null)}>
        <label>{t("trace.code")} <input value={code} onChange={(e) => setCode(e.target.value)} /></label>{" "}
        <button disabled={busy}>{t("trace.search")}</button>
      </form>
      <form onSubmit={(e) => go(e, sha.trim() ? { sha256: sha.trim() } : null)}>
        <label>{t("trace.sha256")} <input value={sha} onChange={(e) => setSha(e.target.value)} /></label>{" "}
        <button disabled={busy}>{t("trace.search")}</button>
      </form>
      <form onSubmit={(e) => go(e, file)}>
        <label>{t("trace.file")} <input type="file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} /></label>{" "}
        <button disabled={busy}>{t("trace.search")}</button>
      </form>
      {err && <p className="error" role="alert">{t("trace.error")}</p>}
      {res && (
        <>
          {!res.analyzed && <p>{t("trace.notAnalyzed")}</p>}
          {res.hits.length === 0 ? <p>{t("trace.undetermined")}</p> : (
            <table>
              <thead>
                <tr>
                  {["source", "method", "code", "file", "owner", "recipient", "ip", "at"].map((k) => <th key={k}>{t(`trace.col.${k}`)}</th>)}
                </tr>
              </thead>
              <tbody>
                {res.hits.map((h, i) => (
                  <tr key={i}>
                    <td>{h.source}{h.via ? ` / ${h.via}` : ""}</td><td>{h.method}</td><td>{h.code}</td><td>{h.file_name}</td>
                    <td>{h.owner_email}</td><td>{h.recipient_email}</td><td>{h.ip}</td><td>{fmtDate(h.at, i18n.language)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </>
  );
}
