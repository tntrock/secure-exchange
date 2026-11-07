import { useEffect, useState } from "react";
import QRCode from "qrcode";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { api, ApiError } from "../api";
import LangSwitch from "../components/LangSwitch";

// only same-origin absolute paths: a crafted `from` like //evil.example must not redirect off-site
export const safeFrom = (v: unknown): string | null => (typeof v === "string" && v.startsWith("/") && !v.startsWith("//") && !v.startsWith("/\\") ? v : null);

export default function Login() {
  const { t } = useTranslation();
  const nav = useNavigate();
  const from = safeFrom((useLocation().state as { from?: unknown } | null)?.from);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [mfa, setMfa] = useState(false);
  const [qr, setQr] = useState(""); // forced TOTP enrolment
  const [err, setErr] = useState("");
  const [ldap, setLdap] = useState(false);
  const [user, setUser] = useState("");
  const [dpw, setDpw] = useState("");
  const [lerr, setLerr] = useState("");
  const [oidc, setOidc] = useState<{ label: string } | null>(null);
  const oerr = useSearchParams()[0].get("oidc_error");
  const OIDC_MSG: Record<string, string> = { denied: "login.oidcDenied", unavailable: "login.oidcUnavailable", email_conflict: "login.oidcEmailConflict", rate_limited: "login.rateLimited" };
  const oidcMsg = oerr && Object.hasOwn(OIDC_MSG, oerr) ? OIDC_MSG[oerr] : "login.oidcInvalid";

  useEffect(() => { api.authMethods().then((m) => { setLdap(!!m?.ldap); setOidc(m?.oidc ? { label: m.oidc_label ?? "" } : null); }, () => {}); }, []);

  const fail = (e: unknown, invalidKey: string) =>
    setErr(e instanceof ApiError && e.status === 429 ? t("login.rateLimited") : e instanceof ApiError && e.status === 401 ? t(invalidKey) : t("app.error"));

  // vendors land on their portal; a failed /api/me falls back to the staff home
  const home = async () => nav(from ?? ((await api.me().catch(() => null))?.role === "vendor" ? "/vendor/shares" : "/files"));

  const submit = async (ev: React.FormEvent) => {
    ev.preventDefault();
    setErr("");
    try {
      if (!mfa && !qr) {
        const r = await api.login(email, password);
        if (r.totp_setup_required) setQr(await QRCode.toDataURL((await api.totpSetupPending()).otpauth_url, { margin: 1, width: 220 }));
        else if (r.mfa_required) setMfa(true);
        else await home();
      } else if (qr) {
        await api.totpEnroll(code);
        await home();
      } else {
        await api.totp(code);
        await home();
      }
    } catch (e) {
      if ((mfa || qr) && e instanceof ApiError && e.status === 401 && e.message === "unauthorized") {
        // the 10-minute half session expired: start over from the password step
        setMfa(false); setQr(""); setCode(""); setErr(t("login.sessionTimedOut"));
        return;
      }
      fail(e, mfa || qr ? "login.invalidCode" : "login.invalid");
    }
  };

  const submitLdap = async (ev: React.FormEvent) => {
    ev.preventDefault();
    setLerr("");
    try {
      await api.ldapLogin(user, dpw);
      nav(from ?? "/files"); // directory users are staff/admin, never vendors
    } catch (e) {
      const s = e instanceof ApiError ? e.status : 0;
      setLerr(s === 503 ? t("login.directoryUnavailable") : s === 409 ? t("login.emailConflict") : s === 429 ? t("login.rateLimited") : s === 401 ? t("login.invalid") : t("app.error"));
    }
  };

  return (
    <main>
      <div style={{ textAlign: "right" }}><LangSwitch /></div>
      <h1>{mfa || qr ? t("login.totpTitle") : t("login.title")}</h1>
      <form onSubmit={submit}>
        {!mfa && !qr ? (
          <>
            <label>
              {t("login.email")}
              <input type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} />
            </label>
            <label>
              {t("login.password")}
              <input type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
            </label>
          </>
        ) : (
          <>
            {qr && <><p>{t("totp.scan")}</p><img src={qr} alt={t("totp.qrAlt")} width={220} height={220} /></>}
          <label>
            {t("login.totpCode")}
            <input inputMode="numeric" autoComplete="one-time-code" required autoFocus value={code} onChange={(e) => setCode(e.target.value)} />
          </label>
          </>
        )}
        {err && <p className="error" role="alert">{err}</p>}
        <button type="submit">{mfa || qr ? t("login.totpSubmit") : t("login.submit")}</button>
      </form>
      {oerr !== null && !mfa && !qr && <p className="error" role="alert">{t(oidcMsg)}</p>}
      {oidc && !mfa && !qr && (
        <>
          <p style={{ textAlign: "center" }}>{t("login.or")}</p>
          <a href="/api/auth/oidc/start">{oidc.label || t("login.oidcDefault")}</a>
        </>
      )}
      {ldap && !mfa && !qr && (
        <>
          <h2>{t("login.domainTitle")}</h2>
          <form onSubmit={submitLdap}>
            <label>
              {t("login.username")}
              <input type="text" autoComplete="username" required value={user} onChange={(e) => setUser(e.target.value)} />
            </label>
            <label>
              {t("login.password")}
              <input type="password" autoComplete="current-password" required value={dpw} onChange={(e) => setDpw(e.target.value)} />
            </label>
            {lerr && <p className="error" role="alert">{lerr}</p>}
            <button type="submit">{t("login.submit")}</button>
          </form>
        </>
      )}
    </main>
  );
}
