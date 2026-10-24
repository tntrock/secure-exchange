import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Link, Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import "./i18n";
import LangSwitch from "./components/LangSwitch";
import { api, ApiError } from "./api";
import Login from "./pages/Login";
import Files from "./pages/Files";
import Shares from "./pages/Shares";
import ShareDetail from "./pages/ShareDetail";
import TotpSetup from "./pages/TotpSetup";
import "./style.css";

function Shell({ children }: { children: React.ReactNode }) {
  const { t } = useTranslation();
  const nav = useNavigate();
  return (
    <>
      <header>
        <strong>{t("app.title")}</strong>
        <Link to="/files">{t("nav.files")}</Link>
        <Link to="/shares">{t("nav.shares")}</Link>
        <span className="spacer" />
        <LangSwitch />
        <button onClick={() => api.logout().finally(() => nav("/login"))}>{t("app.logout")}</button>
      </header>
      <main>{children}</main>
    </>
  );
}

// Loads /api/me and redirects to /login on 401.
function Private({ children }: { children: React.ReactNode }) {
  const { t } = useTranslation();
  const [ok, setOk] = useState<boolean | null>(null);
  useEffect(() => {
    api.me().then(
      () => setOk(true),
      (e) => setOk(!(e instanceof ApiError && e.status === 401)),
    );
  }, []);
  if (ok === null) return <p>{t("app.loading")}</p>;
  return ok ? <Shell>{children}</Shell> : <Navigate to="/login" replace />;
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/files" element={<Private><Files /></Private>} />
        <Route path="/shares" element={<Private><Shares /></Private>} />
        <Route path="/shares/:id" element={<Private><ShareDetail /></Private>} />
        <Route path="/settings/totp" element={<Private><TotpSetup /></Private>} />
        <Route path="*" element={<Navigate to="/files" replace />} />
      </Routes>
    </BrowserRouter>
  </StrictMode>,
);
