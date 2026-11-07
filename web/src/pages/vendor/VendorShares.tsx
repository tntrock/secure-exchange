import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { errKey } from "../recipient/errKey";
import { api, fmtDate, type VendorShareSummary } from "../../api";

export default function VendorShares() {
  const { t, i18n } = useTranslation();
  const [rows, setRows] = useState<VendorShareSummary[] | null>(null);
  const [err, setErr] = useState("");
  useEffect(() => { api.vendorShares().then(setRows, (e) => setErr(errKey(e))); }, []);
  return (
    <>
      <h1>{t("vendorPortal.title")}</h1>
      {err && <p className="error" role="alert">{t(`recipient.error.${err}`)}</p>}
      {rows && !rows.length && <p>{t("vendorPortal.empty")}</p>}
      {rows && rows.length > 0 && (
        <table>
          <thead>
            <tr><th>{t("vendorPortal.owner")}</th><th>{t("vendorPortal.message")}</th><th>{t("vendorPortal.expires")}</th><th>{t("vendorPortal.files")}</th><th /></tr>
          </thead>
          <tbody>
            {rows.map((s) => (
              <tr key={s.id}>
                <td>{s.owner_name}</td>
                <td>{s.message}</td>
                <td>{fmtDate(s.expires_at, i18n.language)}</td>
                <td>{s.file_count}</td>
                <td><Link to={`/vendor/shares/${s.id}`}>{t("vendorPortal.open")}</Link></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
