import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError, fmtDate, type UserAction, type UserInfo } from "../../api";

const ERR: Record<string, string> = { last_admin: "lastAdmin", external_account: "external", email_taken: "emailTaken", wrong_state: "wrongState" };

export default function Users() {
  const { t, i18n } = useTranslation();
  const [rows, setRows] = useState<UserInfo[]>([]);
  const [listErr, setListErr] = useState("");
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState("staff");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(() => {
    api.adminUsers().then((v) => setRows(v ?? []), () => setListErr(t("app.error")));
  }, [t]);
  useEffect(refresh, [refresh]);

  const act = async (p: Promise<unknown>) => {
    setErr("");
    setBusy(true);
    try {
      await p;
      refresh();
    } catch (e) {
      const k = e instanceof ApiError ? ERR[e.message] : undefined;
      setErr(t(`users.error.${k ?? "generic"}`));
    }
    setBusy(false);
  };

  const submit = (ev: React.FormEvent) => {
    ev.preventDefault();
    void act(api.adminCreateUser(email.trim(), name.trim(), role).then(() => { setEmail(""); setName(""); }));
  };

  const btn = (u: UserInfo, a: UserAction, label: string, ask = "") => (
    <button disabled={busy} onClick={() => (!ask || confirm(t(ask, { email: u.email }))) && act(api.adminUserAction(u.id, a))}>{t(label)}</button>
  );

  const roleSelect = (value: string, label: string, onChange: (v: string) => void) => (
    <select aria-label={label} value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="staff">{t("users.roles.staff")}</option>
      <option value="admin">{t("users.roles.admin")}</option>
    </select>
  );

  return (
    <>
      <h1>{t("users.title")}</h1>
      <form onSubmit={submit}>
        <h2>{t("users.new")}</h2>
        {err && <p className="error" role="alert">{err}</p>}
        <label>{t("users.email")}<input value={email} onChange={(e) => setEmail(e.target.value)} /></label>
        <label>{t("users.name")}<input value={name} onChange={(e) => setName(e.target.value)} /></label>
        <label>{t("users.role")}
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="staff">{t("users.roles.staff")}</option>
            <option value="admin">{t("users.roles.admin")}</option>
          </select>
        </label>
        <button type="submit" disabled={busy}>{t("users.create")}</button>
      </form>
      {listErr && <p className="error" role="alert">{listErr}</p>}
      <h2>{t("users.listTitle")}</h2>
      <table>
        <thead>
          <tr>
            <th>{t("users.email")}</th><th>{t("users.name")}</th><th>{t("users.role")}</th><th>{t("users.source")}</th>
            <th>{t("users.statusLabel")}</th><th>{t("users.totp")}</th><th>{t("users.lastLogin")}</th><th />
          </tr>
        </thead>
        <tbody>
          {rows.map((u) => (
            <tr key={u.id}>
              <td>{u.email}</td><td>{u.display_name}</td>
              <td>{u.auth_source === "local" && u.role !== "vendor"
                ? roleSelect(u.role, `${t("users.role")}: ${u.email}`, (v) => (u.role === "admin" && v === "staff" && !confirm(t("users.confirmDemote", { email: u.email }))) || void act(api.adminSetRole(u.id, v)))
                : t(`users.roles.${u.role}`)}</td>
              <td>{t(`users.sources.${u.auth_source}`, { defaultValue: u.auth_source })}</td>
              <td>{t(`users.status.${u.status}`)}</td>
              <td>{t(u.totp_enabled ? "users.yes" : "users.no")}</td>
              <td>{u.last_login_at ? fmtDate(u.last_login_at, i18n.language) : t("users.never")}</td>
              <td>
                {u.status === "disabled" ? btn(u, "enable", "users.enable") : btn(u, "disable", "users.disable", "users.confirmDisable")}{" "}
                {u.totp_enabled && btn(u, "reset-totp", "users.resetTotp", "users.confirmReset")}{" "}
                {u.status === "invited" && u.role !== "vendor" && btn(u, "reinvite", "users.reinvite")}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
