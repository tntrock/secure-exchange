import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, type AuditQuery, type AuditRow } from "../../api";

const iso = (v: string) => (v ? new Date(v).toISOString() : "");

export default function Audit() {
  const { t } = useTranslation();
  const [f, setF] = useState({ since: "", until: "", actor: "", action: "", target: "" });
  const [applied, setApplied] = useState<AuditQuery>({});
  const [stack, setStack] = useState<number[]>([]); // `before` of earlier pages
  const [cur, setCur] = useState(0);
  const [rows, setRows] = useState<AuditRow[]>([]);
  const [next, setNext] = useState(0);
  const [err, setErr] = useState(false);
  const [verify, setVerify] = useState("");

  useEffect(() => {
    let off = false;
    setErr(false);
    api.auditList({ ...applied, before: cur || undefined }).then((r) => { if (off) return; setRows(r.entries ?? []); setNext(r.next_before); }, () => { if (!off) setErr(true); });
    return () => { off = true; };
  }, [applied, cur]);

  const field = (k: keyof typeof f, type = "text") => (
    <label>{t(`audit.${k}`)} <input type={type} value={f[k]} onChange={(e) => setF({ ...f, [k]: e.target.value })} /></label>
  );

  return (
    <>
      <h1>{t("audit.title")}</h1>
      <form onSubmit={(e) => {
        e.preventDefault();
        setStack([]); setCur(0);
        setApplied({ since: iso(f.since), until: iso(f.until), actor: f.actor.trim(), action: f.action.trim(), target: f.target.trim() });
      }}>
        {field("since", "datetime-local")} {field("until", "datetime-local")} {field("actor")} {field("action")} {field("target")}
        <button type="submit">{t("audit.filter")}</button>
      </form>
      <p>
        <a href={api.auditExportURL(applied)}>{t("audit.export")}</a>{" "}
        <button onClick={() => api.auditVerify().then((r) => setVerify(r.bad_id ? t("audit.verifyBad", { id: r.bad_id }) : t("audit.verifyOk", { n: r.checked })), () => setErr(true))}>{t("audit.verify")}</button>
      </p>
      {verify && <p role="status">{verify}</p>}
      {err && <p className="error" role="alert">{t("app.error")}</p>}
      {rows.length === 0 ? <p>{t("audit.empty")}</p> : (
        <table>
          <thead><tr><th>{t("audit.time")}</th><th>{t("audit.actor")}</th><th>{t("audit.ip")}</th><th>{t("audit.action")}</th><th>{t("audit.target")}</th><th>{t("audit.result")}</th><th>{t("audit.detail")}</th></tr></thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td>{new Date(r.at).toLocaleString()}</td><td>{r.actor_label || r.actor_id}</td><td>{r.ip}</td><td>{r.action}</td>
                <td>{r.target_type}{r.target_id && `:${r.target_id}`}</td><td>{r.result}</td><td>{Object.keys(r.detail).length > 0 && JSON.stringify(r.detail)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p>
        <button disabled={stack.length === 0} onClick={() => { setCur(stack[stack.length - 1]); setStack(stack.slice(0, -1)); }}>{t("audit.prev")}</button>{" "}
        <button disabled={!next} onClick={() => { setStack([...stack, cur]); setCur(next); }}>{t("audit.next")}</button>
      </p>
    </>
  );
}
