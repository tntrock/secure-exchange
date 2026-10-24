import { useTranslation } from "react-i18next";
import { setLanguage } from "../i18n";

export default function LangSwitch() {
  const { t, i18n } = useTranslation();
  return (
    <select aria-label={t("app.language")} value={i18n.language} onChange={(e) => setLanguage(e.target.value)}>
      <option value="zh-TW">繁體中文</option>
      <option value="en">English</option>
    </select>
  );
}
