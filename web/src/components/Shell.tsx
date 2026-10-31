import { Link, useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import LangSwitch from "./LangSwitch";
import { api } from "../api";

export default function Shell({ role, children }: { role: string; children: React.ReactNode }) {
  const { t } = useTranslation();
  const nav = useNavigate();
  return (
    <>
      <header>
        <strong>{t("app.title")}</strong>
        <Link to="/files">{t("nav.files")}</Link>
        <Link to="/shares">{t("nav.shares")}</Link>
        {role === "admin" && <Link to="/admin/trace">{t("nav.trace")}</Link>}
        <span className="spacer" />
        <LangSwitch />
        <button onClick={() => api.logout().finally(() => nav("/login"))}>{t("app.logout")}</button>
      </header>
      <main>{children}</main>
    </>
  );
}
