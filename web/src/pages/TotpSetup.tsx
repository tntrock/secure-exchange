import { useState } from "react";
import QRCode from "qrcode";
import { useTranslation } from "react-i18next";
import { api } from "../api";

export default function TotpSetup() {
  const { t } = useTranslation();
  const [qr, setQr] = useState("");
  const [code, setCode] = useState("");
  const [err, setErr] = useState("");
  const [enabled, setEnabled] = useState(false);

  const start = async () => {
    setErr("");
    try {
      const { otpauth_url } = await api.totpSetup();
      setQr(await QRCode.toDataURL(otpauth_url, { margin: 1, width: 220 }));
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
      {enabled ? (
        <p>{t("totp.enabled")}</p>
      ) : !qr ? (
        <button onClick={start}>{t("totp.start")}</button>
      ) : (
        <>
          <p>{t("totp.scan")}</p>
          <img src={qr} alt={t("totp.qrAlt")} width={220} height={220} />
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
