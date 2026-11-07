import { Link, useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import LangSwitch from "./LangSwitch";
import { useEffect, useState } from "react";
import { api } from "../api";

export default function Shell({ role, version, children }: { role: string; version?: string; children: React.ReactNode }) {
  const { t } = useTranslation();
  const nav = useNavigate();
  const [fwdAlert, setFwdAlert] = useState(false);
  useEffect(() => {
    if (role === "admin") api.auditForwarding().then((s) => setFwdAlert(!!s?.alert), () => {});
  }, [role]);
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
        {role === "admin" && <Link to="/admin/shares">{t("nav.allShares")}</Link>}
        {role === "admin" && <Link to="/admin/trace">{t("nav.trace")}</Link>}
        {role === "admin" && <Link to="/admin/rules">{t("nav.rules")}</Link>}
        {role === "admin" && <Link to="/admin/audit">{t("nav.audit")}</Link>}
        {role !== "vendor" && <Link to="/settings">{t("nav.settings")}</Link>}
        <span className="spacer" />
        <LangSwitch />
        <button onClick={() => api.logout().finally(() => nav("/login"))}>{t("app.logout")}</button>
      </header>
      {fwdAlert && <p className="error" role="alert">{t("audit.fwdAlert")}</p>}
      <main>{children}</main>
      {role === "admin" && version && <footer>{t("nav.version", { version })}</footer>}
    </>
  );
}
