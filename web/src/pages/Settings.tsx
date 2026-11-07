import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { api, type NotifyPrefs } from "../api";
import { useExternal } from "../useExternal";

const KEYS = ["first_open", "download", "upload"] as const;

export default function Settings() {
  const { t } = useTranslation();
  const [p, setP] = useState<NotifyPrefs | null>(null);
  const [err, setErr] = useState(false);
  const [saved, setSaved] = useState(false);
  const external = useExternal();
  useEffect(() => { api.getNotifyPrefs().then(setP, () => setErr(true)); }, []);
  const save = () => {
    setSaved(false);
    setErr(false);
    api.putNotifyPrefs(p!).then(() => setSaved(true), () => setErr(true));
  };
  return (
    <>
      <h1>{t("settings.title")}</h1>
      {err && <p className="error" role="alert">{t("app.error")}</p>}
      {p && (
        <>
          <h2>{t("settings.notify")}</h2>
          {KEYS.map((k) => (
            <p key={k}><label><input type="checkbox" checked={p[k]} onChange={(e) => { setSaved(false); setP({ ...p, [k]: e.target.checked }); }} /> {t(`settings.${k}`)}</label></p>
          ))}
          <p><em>{t("settings.virusNote")}</em></p>
          <button onClick={save}>{t("settings.save")}</button>
          {saved && <p role="status">{t("settings.saved")}</p>}
        </>
      )}
      {external === false && <p><Link to="/settings/totp">{t("settings.totp")}</Link></p>}
    </>
  );
}
