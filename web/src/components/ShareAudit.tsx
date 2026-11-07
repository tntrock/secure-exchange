import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, type AuditRow } from "../api";

export default function ShareAudit({ id, admin }: { id: string; admin: boolean }) {
  const { t } = useTranslation();
  const [rows, setRows] = useState<AuditRow[] | null>(null);
  const [err, setErr] = useState(false);
  useEffect(() => {
    api.shareAudit(id, admin).then((r) => setRows(r.entries ?? []), () => setErr(true));
  }, [id, admin]);
  return (
    <>
      <h2>{t("audit.shareTitle")}</h2>
      {err && <p className="error" role="alert">{t("app.error")}</p>}
      {rows && (rows.length === 0 ? <p>{t("audit.empty")}</p> : (
        <table>
          <thead><tr><th>{t("audit.time")}</th><th>{t("audit.actor")}</th><th>{t("audit.action")}</th><th>{t("audit.ip")}</th><th>{t("audit.result")}</th></tr></thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td>{new Date(r.at).toLocaleString()}</td><td>{r.actor_label || r.actor_id}</td><td>{r.action}</td><td>{r.ip}</td><td>{r.result}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ))}
    </>
  );
}
