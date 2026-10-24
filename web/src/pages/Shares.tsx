import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { api, fmtDate, type ShareSummary } from "../api";

export default function Shares() {
  const { t, i18n } = useTranslation();
  const [rows, setRows] = useState<ShareSummary[]>([]);
  const [err, setErr] = useState("");
  useEffect(() => {
    api.shares().then((r) => setRows(r ?? []), () => setErr(t("app.error")));
  }, [t]);

  const status = (s: ShareSummary) => t(s.revoked ? "share.status.revoked" : s.expired ? "share.status.expired" : "share.status.active");

  return (
    <>
      <h1>{t("share.listTitle")}</h1>
      {err && <p className="error" role="alert">{err}</p>}
      {rows.length === 0 ? (
        <p>{t("share.empty")}</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>{t("share.createdAt")}</th><th>{t("share.expiresAt")}</th><th>{t("share.settings")}</th>
              <th>{t("share.files")}</th><th>{t("share.recipientCount")}</th><th>{t("share.views")}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((s) => (
              <tr key={s.id}>
                <td><Link to={`/shares/${s.id}`}>{fmtDate(s.created_at, i18n.language)}</Link></td>
                <td>{fmtDate(s.expires_at, i18n.language)}</td>
                <td>{status(s)}</td>
                <td>{s.file_count}</td>
                <td>{s.recipient_count}</td>
                <td>{s.max_views == null ? s.view_count : `${s.view_count} / ${s.max_views}`}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
