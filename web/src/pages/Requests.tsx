import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { api, ApiError, fmtDate, fmtSize, type UploadRequest } from "../api";

const lines = (s: string) => s.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);

// <input type="date"> wants local "YYYY-MM-DD".
const defaultDay = () => {
  const d = new Date(Date.now() + 7 * 864e5);
  d.setMinutes(d.getMinutes() - d.getTimezoneOffset());
  return d.toISOString().slice(0, 10);
};

export default function Requests() {
  const { t, i18n } = useTranslation();
  const nav = useNavigate();
  const [rows, setRows] = useState<UploadRequest[]>([]);
  const [listErr, setListErr] = useState("");
  const [emails, setEmails] = useState("");
  const [expires, setExpires] = useState(defaultDay);
  const [maxFiles, setMaxFiles] = useState("10");
  const [maxGb, setMaxGb] = useState("10");
  const [exts, setExts] = useState("");
  const [message, setMessage] = useState("");
  const [err, setErr] = useState<{ field: string; msg: string } | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.requests().then((r) => setRows(r ?? []), () => setListErr(t("app.error")));
  }, [t]);

  const fieldErr = (f: string) => err?.field === f && <span className="error" role="alert">{err.msg}</span>;

  const submit = async (ev: React.FormEvent) => {
    ev.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      const d = new Date(`${expires}T23:59:59`); // end of the chosen local day
      const r = await api.createRequest({
        emails: lines(emails),
        expires_at: isNaN(d.getTime()) ? "" : d.toISOString(),
        max_files: Number(maxFiles),
        max_total_bytes: Math.round(Number(maxGb) * 1024 ** 3),
        allowed_exts: lines(exts).map((e) => e.replace(/^\./, "")),
        message,
      });
      nav(`/requests/${r.id}`);
    } catch (e) {
      const key = e instanceof ApiError && e.status === 422 ? `requests.error.${e.field}.${e.code}` : "";
      const known = key !== "" && i18n.exists(key);
      setErr({ field: known ? ((e as ApiError).field ?? "") : "", msg: t(known ? key : "requests.error.generic") });
      setBusy(false);
    }
  };

  const status = (r: UploadRequest) => t(r.revoked ? "requests.status.revoked" : r.expired ? "requests.status.expired" : "requests.status.active");

  return (
    <>
      <h1>{t("requests.title")}</h1>
      <form onSubmit={submit}>
        <h2>{t("requests.new")}</h2>
        {err && !err.field && <p className="error" role="alert">{err.msg}</p>}
        <label>{t("requests.emails")}
          <textarea rows={2} value={emails} onChange={(e) => setEmails(e.target.value)} />
          {fieldErr("emails")}
        </label>
        <label>{t("requests.expiresOn")}
          <input type="date" value={expires} onChange={(e) => setExpires(e.target.value)} />
          {fieldErr("expires_at")}
        </label>
        <label>{t("requests.maxFiles")}
          <input type="number" min={1} value={maxFiles} onChange={(e) => setMaxFiles(e.target.value)} />
          {fieldErr("max_files")}
        </label>
        <label>{t("requests.maxGb")}
          <input type="number" min={0.001} step="any" value={maxGb} onChange={(e) => setMaxGb(e.target.value)} />
          {fieldErr("max_total_bytes")}
        </label>
        <label>{t("requests.exts")}
          <input value={exts} onChange={(e) => setExts(e.target.value)} />
          {fieldErr("allowed_exts")}
        </label>
        <label>{t("requests.message")}
          <textarea rows={2} maxLength={2000} value={message} onChange={(e) => setMessage(e.target.value)} />
          {fieldErr("message")}
        </label>
        <button type="submit" disabled={busy}>{t("requests.create")}</button>
      </form>
      <h2>{t("requests.listTitle")}</h2>
      {listErr && <p className="error" role="alert">{listErr}</p>}
      {rows.length === 0 ? (
        <p>{t("requests.empty")}</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>{t("requests.createdAt")}</th><th>{t("requests.expiresAt")}</th><th>{t("requests.statusLabel")}</th>
              <th>{t("requests.files")}</th><th>{t("requests.size")}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td><Link to={`/requests/${r.id}`}>{fmtDate(r.created_at, i18n.language)}</Link></td>
                <td>{fmtDate(r.expires_at, i18n.language)}</td>
                <td>{status(r)}</td>
                <td>{r.file_count} / {r.max_files}</td>
                <td>{fmtSize(r.total_bytes, i18n.language)} / {fmtSize(r.max_total_bytes, i18n.language)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
