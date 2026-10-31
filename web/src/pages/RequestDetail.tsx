import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { api, fmtDate, fmtSize, type UploadRequestDetail } from "../api";
import ScanBadge from "../components/ScanBadge";

export default function RequestDetail() {
  const { id = "" } = useParams();
  const { t, i18n } = useTranslation();
  const [d, setD] = useState<UploadRequestDetail | null>(null);
  const [err, setErr] = useState("");
  const [copied, setCopied] = useState(false);

  const refresh = useCallback(() => {
    api.request(id).then(setD, () => setErr(t("app.error")));
  }, [id, t]);
  useEffect(refresh, [refresh]);
  // scans finish in the background
  const pending = d?.files.some((f) => f.scan_status === "pending");
  useEffect(() => {
    if (!pending) return;
    const i = setInterval(refresh, 5000);
    return () => clearInterval(i);
  }, [pending, refresh]);

  const revoke = async () => {
    if (!confirm(t("requests.confirmRevoke"))) return;
    try {
      await api.revokeRequest(id);
      refresh();
    } catch {
      setErr(t("app.error"));
    }
  };
  const copy = () => navigator.clipboard.writeText(d!.url).then(() => setCopied(true), () => setErr(t("app.error")));

  if (!d) return err ? <p className="error" role="alert">{err}</p> : <p>{t("app.loading")}</p>;
  const date = (s: string | null) => (s ? fmtDate(s, i18n.language) : t("requests.never"));
  const status = t(d.revoked ? "requests.status.revoked" : d.expired ? "requests.status.expired" : "requests.status.active");

  return (
    <>
      <p><Link to="/requests">{t("requests.back")}</Link></p>
      <h1>{t("requests.detailTitle")}</h1>
      {err && <p className="error" role="alert">{err}</p>}
      <ul>
        <li>{t("requests.link")}: <code>{d.url}</code>{" "}<button onClick={copy}>{copied ? t("requests.copied") : t("requests.copy")}</button></li>
        <li>{t("requests.createdAt")}: {date(d.created_at)}</li>
        <li>{t("requests.expiresAt")}: {date(d.expires_at)}</li>
        <li>{t("requests.statusLabel")}: {status}</li>
        <li>{t("requests.files")}: {d.file_count} / {d.max_files}</li>
        <li>{t("requests.size")}: {fmtSize(d.total_bytes, i18n.language)} / {fmtSize(d.max_total_bytes, i18n.language)}</li>
        <li>{t("requests.allowedExts")}: {d.allowed_exts.length ? d.allowed_exts.join(", ") : t("requests.anyExt")}</li>
        {d.message && <li>{t("requests.message")}: {d.message}</li>}
      </ul>
      {!d.revoked && <button onClick={revoke}>{t("requests.revoke")}</button>}
      <h2>{t("requests.uploaders")}</h2>
      <table>
        <thead><tr><th>{t("requests.email")}</th><th>{t("requests.firstOpened")}</th><th>{t("requests.lastAccess")}</th></tr></thead>
        <tbody>
          {d.uploaders.map((u) => (
            <tr key={u.id}><td>{u.email}</td><td>{date(u.first_opened_at)}</td><td>{date(u.last_access_at)}</td></tr>
          ))}
        </tbody>
      </table>
      <h2>{t("requests.fileList")}</h2>
      <table>
        <thead>
          <tr><th>{t("files.name")}</th><th>{t("files.size")}</th><th>{t("requests.uploader")}</th><th>{t("files.created")}</th><th>{t("scan.label")}</th></tr>
        </thead>
        <tbody>
          {d.files.map((f) => (
            <tr key={f.id}>
              <td>{f.name}{f.deleted && <> {t("requests.deleted")}</>}</td>
              <td>{fmtSize(f.size, i18n.language)}</td>
              <td>{f.uploader_email}</td>
              <td>{date(f.created_at)}</td>
              <td><ScanBadge status={f.scan_status} result={f.scan_result} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
