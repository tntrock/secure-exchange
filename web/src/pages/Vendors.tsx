import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError, fmtDate, type VendorInfo } from "../api";

// <input type="date"> wants local "YYYY-MM-DD".
const dayStr = (days: number) => {
  const d = new Date(Date.now() + days * 864e5);
  d.setMinutes(d.getMinutes() - d.getTimezoneOffset());
  return d.toISOString().slice(0, 10);
};
const MAX_DAYS = 1095; // the server's cap on a vendor account's lifetime

// End of the chosen local day, kept inside the server's window (after now+1 day, before now+MAX_DAYS).
const toISO = (day: string) => {
  const ms = new Date(`${day}T23:59:59`).getTime();
  if (isNaN(ms)) return "";
  return new Date(Math.min(ms, Date.now() + MAX_DAYS * 864e5 - 6e4)).toISOString();
};

export default function Vendors() {
  const { t, i18n } = useTranslation();
  const [rows, setRows] = useState<VendorInfo[]>([]);
  const [admin, setAdmin] = useState(false);
  const [listErr, setListErr] = useState("");
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [org, setOrg] = useState("");
  const [expires, setExpires] = useState(() => dayStr(365));
  const [err, setErr] = useState<{ field: string; msg: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [editing, setEditing] = useState("");
  const [editDay, setEditDay] = useState("");

  const refresh = useCallback(() => {
    api.vendors().then((v) => setRows(v ?? []), () => setListErr(t("app.error")));
  }, [t]);
  useEffect(refresh, [refresh]);
  useEffect(() => {
    api.me().then((m) => setAdmin(m.role === "admin"), () => {});
  }, []);

  const fail = (e: unknown) => {
    const key = e instanceof ApiError ? (e.status === 422 ? `vendors.error.${e.field}.${e.code}` : `vendors.error.${e.message}`) : "";
    const known = key !== "" && i18n.exists(key);
    setErr({ field: known && e instanceof ApiError && e.status === 422 ? (e.field ?? "") : "", msg: t(known ? key : "vendors.error.generic") });
  };
  const fieldErr = (f: string) => err?.field === f && <span className="error" role="alert">{err.msg}</span>;

  const submit = async (ev: React.FormEvent) => {
    ev.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      await api.createVendor({ email: email.trim(), display_name: name.trim(), org: org.trim(), expires_at: toISO(expires) });
      setEmail(""); setName(""); setOrg("");
      refresh();
    } catch (e) {
      fail(e);
    }
    setBusy(false);
  };

  const act = async (p: Promise<unknown>) => {
    setErr(null);
    try {
      await p;
      setEditing("");
      refresh();
    } catch (e) {
      fail(e);
    }
  };

  const pending = admin ? rows.filter((v) => v.status === "pending") : [];
  const others = admin ? rows.filter((v) => v.status !== "pending") : rows;
  const orgs = [...new Set(rows.map((v) => v.org).filter(Boolean))].sort();
  const groups = [...new Set(others.map((v) => v.org))].sort();

  const actions = (v: VendorInfo) => {
    if (!v.can_manage) return null;
    if (editing === v.id) {
      return (
        <>
          <label>{t("vendors.expiresOn")}
            <input type="date" min={dayStr(1)} max={dayStr(MAX_DAYS)} value={editDay} onChange={(e) => setEditDay(e.target.value)} />
          </label>{" "}
          <button onClick={() => act(api.setVendorExpiry(v.id, toISO(editDay)))}>{t("vendors.save")}</button>{" "}
          <button onClick={() => setEditing("")}>{t("share.cancel")}</button>
        </>
      );
    }
    return (
      <>
        {v.status === "disabled"
          ? <button onClick={() => act(api.enableVendor(v.id))}>{t("vendors.enable")}</button>
          : <button onClick={() => act(api.disableVendor(v.id))}>{t("vendors.disable")}</button>}{" "}
        {v.status === "invited" && <><button onClick={() => act(api.reinviteVendor(v.id))}>{t("vendors.reinvite")}</button>{" "}</>}
        <button onClick={() => { setEditing(v.id); setEditDay(v.expires_at.slice(0, 10)); }}>{t("vendors.changeExpiry")}</button>
      </>
    );
  };

  const table = (list: VendorInfo[], extra: (v: VendorInfo) => React.ReactNode) => (
    <table>
      <thead>
        <tr>
          <th>{t("vendors.name")}</th><th>{t("vendors.email")}</th><th>{t("vendors.statusLabel")}</th>
          <th>{t("vendors.expiresAt")}</th><th>{t("vendors.createdBy")}</th><th />
        </tr>
      </thead>
      <tbody>
        {list.map((v) => (
          <tr key={v.id}>
            <td>{v.display_name}</td><td>{v.email}</td><td>{t(`vendors.status.${v.status}`)}</td>
            <td>{fmtDate(v.expires_at, i18n.language)}</td><td>{v.created_by_name}</td><td>{extra(v)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );

  return (
    <>
      <h1>{t("vendors.title")}</h1>
      <form onSubmit={submit}>
        <h2>{t("vendors.new")}</h2>
        {err && !err.field && <p className="error" role="alert">{err.msg}</p>}
        <label>{t("vendors.email")}
          <input value={email} onChange={(e) => setEmail(e.target.value)} />
          {fieldErr("email")}
        </label>
        <label>{t("vendors.name")}
          <input value={name} onChange={(e) => setName(e.target.value)} />
          {fieldErr("display_name")}
        </label>
        <label>{t("vendors.org")}
          <input list="vendor-orgs" value={org} onChange={(e) => setOrg(e.target.value)} />
          {fieldErr("org")}
        </label>
        <datalist id="vendor-orgs">{orgs.map((o) => <option key={o} value={o} />)}</datalist>
        <label>{t("vendors.expiresOn")}
          <input type="date" min={dayStr(1)} max={dayStr(MAX_DAYS)} value={expires} onChange={(e) => setExpires(e.target.value)} />
          {fieldErr("expires_at")}
        </label>
        <button type="submit" disabled={busy}>{t("vendors.create")}</button>
      </form>
      {listErr && <p className="error" role="alert">{listErr}</p>}
      {pending.length > 0 && (
        <section aria-label={t("vendors.pendingTitle")}>
          <h2>{t("vendors.pendingTitle")}</h2>
          {table(pending, (v) => (
            <>
              <button onClick={() => act(api.approveVendor(v.id))}>{t("vendors.approve")}</button>{" "}
              <button onClick={() => confirm(t("vendors.confirmReject", { email: v.email })) && act(api.rejectVendor(v.id))}>{t("vendors.reject")}</button>
            </>
          ))}
        </section>
      )}
      <h2>{t("vendors.listTitle")}</h2>
      {others.length === 0 ? <p>{t("vendors.empty")}</p> : groups.map((g) => (
        <section key={g} aria-label={g || t("vendors.noOrg")}>
          <h3>{g || t("vendors.noOrg")}</h3>
          {table(others.filter((v) => v.org === g), actions)}
        </section>
      ))}
    </>
  );
}
