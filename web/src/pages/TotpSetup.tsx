import { useState } from "react";
import TotpQr from "../components/TotpQr";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { useExternal } from "../useExternal";

export default function TotpSetup() {
  const { t } = useTranslation();
  const [qr, setQr] = useState(""); // otpauth URL once setup started
  const [code, setCode] = useState("");
  const [err, setErr] = useState("");
  const [enabled, setEnabled] = useState(false);
  const external = useExternal();

  const start = async () => {
    setErr("");
    try {
      const { otpauth_url } = await api.totpSetup();
      setQr(otpauth_url);
    } catch {
      setErr(t("totp.failed"));
    }
  };
  const enable = async (ev: React.FormEvent) => {
    ev.preventDefault();
    setErr("");
    try {
      await api.totpEnable(code);
      setEnabled(true);
    } catch {
      setErr(t("totp.failed"));
    }
  };

  return (
    <>
      <h1>{t("totp.title")}</h1>
      {external === null ? null : external ? (
        <p>{t("totp.external")}</p>
      ) : enabled ? (
        <p>{t("totp.enabled")}</p>
      ) : !qr ? (
        <button onClick={start}>{t("totp.start")}</button>
      ) : (
        <>
          <TotpQr url={qr} />
          <form onSubmit={enable}>
            <label>
              {t("totp.code")}
              <input inputMode="numeric" autoComplete="one-time-code" required value={code} onChange={(e) => setCode(e.target.value)} />
            </label>
            <button type="submit">{t("totp.enable")}</button>
          </form>
        </>
      )}
      {err && <p className="error" role="alert">{err}</p>}
    </>
  );
}
