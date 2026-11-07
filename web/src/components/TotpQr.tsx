import { useEffect, useState } from "react";
import QRCode from "qrcode";
import { useTranslation } from "react-i18next";

// QR code plus the secret as text, for authenticator apps that can't scan (or a phone that is the screen).
export default function TotpQr({ url }: { url: string }) {
  const { t } = useTranslation();
  const [src, setSrc] = useState("");
  useEffect(() => {
    let live = true;
    void QRCode.toDataURL(url, { margin: 1, width: 220 }).then((d) => { if (live) setSrc(d); });
    return () => { live = false; };
  }, [url]);
  let secret = "";
  try { secret = new URL(url).searchParams.get("secret") ?? ""; } catch { /* not a URL: show the QR only */ }
  return (
    <>
      <p>{t("totp.scan")}</p>
      {src && <img src={src} alt={t("totp.qrAlt")} width={220} height={220} />}
      {secret && <p>{t("totp.manual")} <code>{secret.match(/.{1,4}/g)!.join(" ")}</code></p>}
    </>
  );
}
