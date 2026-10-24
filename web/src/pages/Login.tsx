import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { api, ApiError } from "../api";
import LangSwitch from "../components/LangSwitch";

export default function Login() {
  const { t } = useTranslation();
  const nav = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [mfa, setMfa] = useState(false);
  const [err, setErr] = useState("");

  const fail = (e: unknown, invalidKey: string) =>
    setErr(e instanceof ApiError && e.status === 429 ? t("login.rateLimited") : e instanceof ApiError && e.status === 401 ? t(invalidKey) : t("app.error"));

  const submit = async (ev: React.FormEvent) => {
    ev.preventDefault();
    setErr("");
    try {
      if (!mfa) {
        const r = await api.login(email, password);
        if (r.mfa_required) setMfa(true);
        else nav("/files");
      } else {
        await api.totp(code);
        nav("/files");
      }
    } catch (e) {
      fail(e, mfa ? "login.invalidCode" : "login.invalid");
    }
  };

  return (
    <main>
      <div style={{ textAlign: "right" }}><LangSwitch /></div>
      <h1>{mfa ? t("login.totpTitle") : t("login.title")}</h1>
      <form onSubmit={submit}>
        {!mfa ? (
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
          <label>
            {t("login.totpCode")}
            <input inputMode="numeric" autoComplete="one-time-code" required autoFocus value={code} onChange={(e) => setCode(e.target.value)} />
          </label>
        )}
        {err && <p className="error" role="alert">{err}</p>}
        <button type="submit">{mfa ? t("login.totpSubmit") : t("login.submit")}</button>
      </form>
    </main>
  );
}
