import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import Uploader from "../../components/Uploader";
import { api, fmtDate, fmtSize, type VendorTarget, type VendorUploadInfo } from "../../api";

export default function VendorUpload() {
  const { t, i18n } = useTranslation();
  const [targets, setTargets] = useState<VendorTarget[] | null>(null);
  const [mine, setMine] = useState<VendorUploadInfo[]>([]);
  const [recipient, setRecipient] = useState("");
  const [err, setErr] = useState("");

  const refresh = useCallback(() => { api.vendorUploads().then(setMine, () => {}); }, []);
  useEffect(() => {
    api.vendorRecipients().then(setTargets, () => setErr("app.error"));
    refresh();
  }, [refresh]);

  const lng = i18n.language;
  return (
    <>
      <h1>{t("vendorPortal.uploadTitle")}</h1>
      {targets && !targets.length && <p>{t("vendorPortal.noRecipients")}</p>}
      {targets && targets.length > 0 && (
        <>
          <label htmlFor="vendor-recipient">{t("vendorPortal.recipient")}</label>
          <select id="vendor-recipient" value={recipient} onChange={(e) => { setRecipient(e.target.value); setErr(""); }}>
            <option value="">{t("vendorPortal.choose")}</option>
            {targets.map((x) => <option key={x.id} value={x.id}>{x.name} ({x.email})</option>)}
          </select>
          {recipient ? (
            <Uploader
              endpoint="/api/vendor/uploads/"
              metadata={{ recipient }}
              onDone={refresh}
              onError={(status, body) => setErr(status === 403 && body.includes("recipient_not_allowed") ? "vendorPortal.notAllowed" : "")}
            />
          ) : (
            <p>{t("vendorPortal.chooseFirst")}</p>
          )}
        </>
      )}
      {err && <p className="error" role="alert">{t(err)}</p>}
      <h2>{t("vendorPortal.yourUploads")}</h2>
      {!mine.length ? <p>{t("vendorPortal.noUploads")}</p> : (
        <table>
          <tbody>
            {mine.map((u) => (
              <tr key={u.id}><td>{u.name}</td><td>{fmtSize(u.size, lng)}</td><td>{u.recipient_name}</td><td>{fmtDate(u.created_at, lng)}</td></tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
