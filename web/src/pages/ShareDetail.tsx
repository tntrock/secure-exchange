import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { api, ApiError, fmtDate, fmtSize, type ShareDetailInfo } from "../api";

export default function ShareDetail() {
  const { id = "" } = useParams();
  const { t, i18n } = useTranslation();
  const [d, setD] = useState<ShareDetailInfo | null>(null);
  const [err, setErr] = useState("");
  const [emails, setEmails] = useState("");

  const refresh = useCallback(() => {
    api.share(id).then(setD, () => setErr(t("app.error")));
  }, [id, t]);
  useEffect(refresh, [refresh]);

  const run = async (p: Promise<unknown>) => {
    setErr("");
    try {
      await p;
      refresh();
    } catch (e) {
      setErr(t(e instanceof ApiError && e.message === "expired" ? "share.error.expired" : "app.error"));
    }
  };

  if (!d) return err ? <p className="error" role="alert">{err}</p> : <p>{t("app.loading")}</p>;
  const date = (s: string | null) => (s ? fmtDate(s, i18n.language) : t("share.never"));
  const yn = (b: boolean) => t(b ? "share.yes" : "share.no");
  const status = t(d.revoked ? "share.status.revoked" : d.expired ? "share.status.expired" : "share.status.active");

  return (
    <>
      <p><Link to="/shares">{t("share.back")}</Link></p>
      <h1>{t("share.detailTitle")}</h1>
      {err && <p className="error" role="alert">{err}</p>}
      <h2>{t("share.settings")}</h2>
      <ul>
        <li>{t("share.createdAt")}: {date(d.created_at)}</li>
        <li>{t("share.expiresAt")}: {date(d.expires_at)}</li>
        <li>{t("share.statusLabel")}: {status}</li>
        <li>{t("share.allowDownload")}: {yn(d.allow_download)}</li>
        <li>{t("share.watermark")}: {yn(d.watermark)}</li>
        <li>{t("share.views")}: {d.max_views == null ? `${d.view_count} (${t("share.unlimited")})` : `${d.view_count} / ${d.max_views}`}</li>
        <li>{t("share.ipAllow")}: {d.ip_allow.length ? d.ip_allow.join(", ") : t("share.none")}</li>
        {d.message && <li>{t("share.message")}: {d.message}</li>}
      </ul>
      {!d.revoked && (
        <button onClick={() => confirm(t("share.confirmRevoke")) && run(api.revokeShare(id))}>{t("share.revokeShare")}</button>
      )}
      <h2>{t("share.fileList")}</h2>
      <ul>
        {d.files.map((f) => (
          <li key={f.id}>{f.name} ({fmtSize(f.size, i18n.language)}){f.deleted && <> {t("share.deleted")}</>}</li>
        ))}
      </ul>
      <h2>{t("share.recipientList")}</h2>
      <table>
        <thead>
          <tr><th>{t("share.email")}</th><th>{t("share.firstOpened")}</th><th>{t("share.lastAccess")}</th><th>{t("share.statusLabel")}</th><th /></tr>
        </thead>
        <tbody>
          {d.recipients.map((r) => (
            <tr key={r.id}>
              <td>{r.email}</td>
              <td>{date(r.first_opened_at)}</td>
              <td>{date(r.last_access_at)}</td>
              <td>{t(r.revoked ? "share.status.revoked" : "share.status.active")}</td>
              <td>
                {!r.revoked && !d.revoked && (
                  <button onClick={() => confirm(t("share.confirmRevokeRecipient", { email: r.email })) && run(api.revokeRecipient(id, r.id))}>
                    {t("share.revoke")}
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {!d.revoked && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const list = emails.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);
            if (list.length) run(api.addRecipients(id, list).then(() => setEmails("")));
          }}
        >
          <label>{t("share.addRecipients")}
            <textarea rows={2} value={emails} onChange={(e) => setEmails(e.target.value)} />
          </label>
          <button type="submit">{t("share.add")}</button>
        </form>
      )}
    </>
  );
}
