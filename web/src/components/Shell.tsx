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
        {role === "vendor" ? (
          <>
            <Link to="/vendor/shares">{t("nav.sharedWithMe")}</Link>
            <Link to="/vendor/upload">{t("nav.vendorUpload")}</Link>
          </>
        ) : (
          <>
            <Link to="/files">{t("nav.files")}</Link>
            <Link to="/shares">{t("nav.shares")}</Link>
            <Link to="/requests">{t("nav.requests")}</Link>
            <Link to="/vendors">{t("nav.vendors")}</Link>
            {role === "admin" && <Link to="/admin/users">{t("nav.users")}</Link>}
          </>
        )}
        {role === "admin" && <Link to="/admin/trace">{t("nav.trace")}</Link>}
        {role === "admin" && <Link to="/admin/rules">{t("nav.rules")}</Link>}
        <span className="spacer" />
        <LangSwitch />
        <button onClick={() => api.logout().finally(() => nav("/login"))}>{t("app.logout")}</button>
      </header>
      <main>{children}</main>
    </>
  );
}
