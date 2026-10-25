import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { api, ApiError } from "../api";

const lines = (s: string) => s.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);

// datetime-local wants local "YYYY-MM-DDTHH:mm".
const localDefault = () => {
  const d = new Date(Date.now() + 7 * 864e5);
  d.setMinutes(d.getMinutes() - d.getTimezoneOffset());
  return d.toISOString().slice(0, 16);
};

export default function ShareDialog({ fileIds, onClose, notReady = false }: { fileIds: string[]; onClose: () => void; notReady?: boolean }) {
  const { t, i18n } = useTranslation();
  const nav = useNavigate();
  const [emails, setEmails] = useState("");
  const [allowDownload, setAllowDownload] = useState(false);
  const [watermark, setWatermark] = useState(true);
  const [expires, setExpires] = useState(localDefault);
  const [maxViews, setMaxViews] = useState("");
  const [ips, setIps] = useState("");
  const [message, setMessage] = useState("");
  const [err, setErr] = useState<{ field: string; msg: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const fail = (e: unknown) => {
    const key = e instanceof ApiError && e.status === 422 ? `share.error.${e.field}.${e.code}` : "";
    const known = key !== "" && i18n.exists(key);
    setErr({ field: known ? ((e as ApiError).field ?? "") : "", msg: t(known ? key : "share.error.generic") });
  };
  const fieldErr = (f: string) => err?.field === f && <span className="error" role="alert">{err.msg}</span>;

  const submit = async (ev: React.FormEvent) => {
    ev.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      const d = new Date(expires);
      const r = await api.createShare({
        file_ids: fileIds,
        emails: lines(emails),
        allow_download: allowDownload,
        watermark,
        expires_at: isNaN(d.getTime()) ? "" : d.toISOString(),
        max_views: maxViews === "" ? null : Number(maxViews),
        ip_allow: lines(ips),
        message,
      });
      nav(`/shares/${r.id}`);
    } catch (e) {
      fail(e);
      setBusy(false);
    }
  };

  return (
    <div className="modal" role="dialog" aria-label={t("share.title")}>
      <form onSubmit={submit}>
        <h2>{t("share.title")}</h2>
        {err && !err.field && <p className="error" role="alert">{err.msg}</p>}
        {fieldErr("file_ids")}
        <label>{t("share.recipients")}
          <textarea rows={3} value={emails} onChange={(e) => setEmails(e.target.value)} />
          {fieldErr("emails")}
        </label>
        <label className="check"><input type="checkbox" checked={allowDownload} onChange={(e) => setAllowDownload(e.target.checked)} />{t("share.allowDownload")}</label>
        {!allowDownload && <p>{t("share.viewOnlyNote")}</p>}
        {!allowDownload && notReady && <p role="status">{t("share.previewHint")}</p>}
        <label className="check"><input type="checkbox" checked={watermark} onChange={(e) => setWatermark(e.target.checked)} />{t("share.watermark")}</label>
        <label>{t("share.expiresAt")}
          <input type="datetime-local" value={expires} onChange={(e) => setExpires(e.target.value)} />
          {fieldErr("expires_at")}
        </label>
        <label>{t("share.maxViews")}
          <input type="number" min={1} value={maxViews} onChange={(e) => setMaxViews(e.target.value)} />
          {fieldErr("max_views")}
        </label>
        <label>{t("share.ipAllow")}
          <textarea rows={2} value={ips} onChange={(e) => setIps(e.target.value)} />
          {fieldErr("ip_allow")}
        </label>
        <label>{t("share.message")}
          <textarea rows={3} maxLength={2000} value={message} onChange={(e) => setMessage(e.target.value)} />
          {fieldErr("message")}
        </label>
        <div>
          <button type="submit" disabled={busy}>{t("share.submit")}</button>{" "}
          <button type="button" onClick={onClose}>{t("share.cancel")}</button>
        </div>
      </form>
    </div>
  );
}
