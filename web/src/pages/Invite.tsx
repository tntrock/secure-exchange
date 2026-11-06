import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import QRCode from "qrcode";
import { useTranslation } from "react-i18next";
import LangSwitch from "../components/LangSwitch";
import { api, ApiError } from "../api";

const MIN_PW = 12;

export default function Invite() {
  const { token = "" } = useParams();
  const { t } = useTranslation();
  const [info, setInfo] = useState<{ email: string; qr: string } | null>(null);
  const [gone, setGone] = useState(false);
  const [loadFailed, setLoadFailed] = useState(""); // i18n key of the load error
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [code, setCode] = useState("");
  const [err, setErr] = useState("");
  const [done, setDone] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const r = await api.inviteInfo(token);
        setInfo({ email: r.email, qr: await QRCode.toDataURL(r.otpauth_url, { margin: 1, width: 220 }) });
      } catch (e) {
        const s = e instanceof ApiError ? e.status : 0;
        if (s === 410 || s === 404) setGone(true);
        else setLoadFailed(e instanceof ApiError && s === 403 && e.message === "ip_denied" ? "recipient.error.ipDenied" : "app.error");
      }
    })();
  }, [token]);

  const submit = async (ev: React.FormEvent) => {
    ev.preventDefault();
    setErr("");
    if (password.length < MIN_PW) return setErr("invite.tooShort");
    if (password !== confirm) return setErr("invite.mismatch");
    try {
      await api.inviteActivate(token, password, code.trim());
      setDone(true);
    } catch (e) {
      const s = e instanceof ApiError ? e.status : 0;
      if (s === 410) setGone(true);
      else setErr(e instanceof ApiError && s === 403 && e.message === "ip_denied" ? "recipient.error.ipDenied" : s === 401 ? "invite.invalidCode" : s === 422 ? (e instanceof ApiError && e.code === "too_short" ? "invite.tooShort" : "invite.badPassword") : "app.error");
    }
  };

  return (
    <main>
      <div style={{ textAlign: "right" }}><LangSwitch /></div>
      <h1>{t("invite.title")}</h1>
      {gone ? <p role="alert">{t("invite.gone")}</p> : loadFailed ? <p role="alert">{t(loadFailed)}</p> : !info ? <p>{t("app.loading")}</p> : done ? (
        <>
          <p>{t("invite.success")}</p>
          <Link to="/login">{t("login.submit")}</Link>
        </>
      ) : (
        <form onSubmit={submit}>
          <p>{t("invite.account", { email: info.email })}</p>
          <p>{t("totp.scan")}</p>
          <img src={info.qr} alt={t("totp.qrAlt")} width={220} height={220} />
          <label>
            {t("login.password")}
            <input type="password" autoComplete="new-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
          </label>
          <label>
            {t("invite.confirm")}
            <input type="password" autoComplete="new-password" required value={confirm} onChange={(e) => setConfirm(e.target.value)} />
          </label>
          <label>
            {t("login.totpCode")}
            <input inputMode="numeric" autoComplete="one-time-code" required value={code} onChange={(e) => setCode(e.target.value)} />
          </label>
          {err && <p className="error" role="alert">{t(err)}</p>}
          <button type="submit">{t("invite.submit")}</button>
        </form>
      )}
    </main>
  );
}
