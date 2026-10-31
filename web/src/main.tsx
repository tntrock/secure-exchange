import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { useTranslation } from "react-i18next";
import "./i18n";
import Shell from "./components/Shell";
import { api, ApiError } from "./api";
import Login from "./pages/Login";
import Files from "./pages/Files";
import Shares from "./pages/Shares";
import ShareDetail from "./pages/ShareDetail";
import Requests from "./pages/Requests";
import RequestDetail from "./pages/RequestDetail";
import UploadPage from "./pages/intake/Upload";
import Trace from "./pages/admin/Trace";
import TotpSetup from "./pages/TotpSetup";
import Access from "./pages/recipient/Access";
import "./style.css";

// Loads /api/me and redirects to /login on 401.
function Private({ children }: { children: React.ReactNode }) {
  const { t } = useTranslation();
  const [ok, setOk] = useState<boolean | null>(null);
  const [role, setRole] = useState("");
  useEffect(() => {
    api.me().then(
      (me) => { setRole(me.role); setOk(true); },
      (e) => setOk(!(e instanceof ApiError && e.status === 401)),
    );
  }, []);
  if (ok === null) return <p>{t("app.loading")}</p>;
  return ok ? <Shell role={role}>{children}</Shell> : <Navigate to="/login" replace />;
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/files" element={<Private><Files /></Private>} />
        <Route path="/shares" element={<Private><Shares /></Private>} />
        <Route path="/shares/:id" element={<Private><ShareDetail /></Private>} />
        <Route path="/requests" element={<Private><Requests /></Private>} />
        <Route path="/requests/:id" element={<Private><RequestDetail /></Private>} />
        <Route path="/settings/totp" element={<Private><TotpSetup /></Private>} />
        <Route path="/admin/trace" element={<Private><Trace /></Private>} />
        <Route path="/s/:token" element={<Access />} />
        <Route path="/r/:token" element={<UploadPage />} />
        <Route path="*" element={<Navigate to="/files" replace />} />
      </Routes>
    </BrowserRouter>
  </StrictMode>,
);
