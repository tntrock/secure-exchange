import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { api, fmtDate } from "../../api";

const PAGE = 100;
interface Row { id: string; created_at: string; expires_at: string; revoked: boolean; expired: boolean; file_count: number; owner_email: string }

export default function AllShares() {
  const { t, i18n } = useTranslation();
  const [tab, setTab] = useState<"shares" | "requests">("shares");
  const [input, setInput] = useState("");
  const [q, setQ] = useState("");
  const [rows, setRows] = useState<Row[]>([]);
  const [more, setMore] = useState(false);
  const [err, setErr] = useState("");

  const load = useCallback((offset: number) => {
    const p = tab === "shares" ? api.adminShares(q, offset) : api.adminRequests(q, offset);
    p.then((r) => {
      const page = r ?? [];
      setRows((old) => (offset ? [...old, ...page] : page));
      setMore(page.length === PAGE);
    }, () => setErr(t("app.error")));
  }, [tab, q, t]);
  useEffect(() => { setErr(""); load(0); }, [load]);

  const status = (r: Row) => t(r.revoked ? "share.status.revoked" : r.expired ? "share.status.expired" : "share.status.active");

  return (
    <>
      <h1>{t("allShares.title")}</h1>
      <p>
        <button disabled={tab === "shares"} onClick={() => setTab("shares")}>{t("allShares.tabShares")}</button>{" "}
        <button disabled={tab === "requests"} onClick={() => setTab("requests")}>{t("allShares.tabRequests")}</button>
      </p>
      <form role="search" onSubmit={(e) => { e.preventDefault(); setQ(input.trim()); }}>
        <input type="search" aria-label={t("allShares.search")} placeholder={t("allShares.search")} value={input} onChange={(e) => setInput(e.target.value)} />
        <button type="submit">{t("allShares.searchBtn")}</button>
      </form>
      {err && <p className="error" role="alert">{err}</p>}
      {rows.length === 0 ? (
        <p>{t("allShares.empty")}</p>
      ) : (
        <table>
          <thead>
            <tr><th>{t("allShares.owner")}</th><th>{t("share.createdAt")}</th><th>{t("share.expiresAt")}</th><th>{t("share.statusLabel")}</th><th>{t("share.files")}</th></tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td>{r.owner_email}</td>
                <td><Link to={`/admin/${tab}/${r.id}`}>{fmtDate(r.created_at, i18n.language)}</Link></td>
                <td>{fmtDate(r.expires_at, i18n.language)}</td>
                <td>{status(r)}</td>
                <td>{r.file_count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {more && <button onClick={() => load(rows.length)}>{t("allShares.more")}</button>}
    </>
  );
}
