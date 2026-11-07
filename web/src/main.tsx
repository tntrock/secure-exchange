import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import "./i18n";
import Private from "./components/Private";
import Login from "./pages/Login";
import Files from "./pages/Files";
import Shares from "./pages/Shares";
import ShareDetail from "./pages/ShareDetail";
import Requests from "./pages/Requests";
import Vendors from "./pages/Vendors";
import RequestDetail from "./pages/RequestDetail";
import UploadPage from "./pages/intake/Upload";
import Trace from "./pages/admin/Trace";
import RulesPage from "./pages/admin/Rules";
import Users from "./pages/admin/Users";
import AllShares from "./pages/admin/AllShares";
import TotpSetup from "./pages/TotpSetup";
import Settings from "./pages/Settings";
import Audit from "./pages/admin/Audit";
import VendorShares from "./pages/vendor/VendorShares";
import VendorShare from "./pages/vendor/VendorShare";
import VendorUpload from "./pages/vendor/VendorUpload";
import Invite from "./pages/Invite";
import Access from "./pages/recipient/Access";
import "./style.css";

const STAFF = ["staff", "admin"];
const VENDOR = ["vendor"];

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/files" element={<Private roles={STAFF}><Files /></Private>} />
        <Route path="/shares" element={<Private roles={STAFF}><Shares /></Private>} />
        <Route path="/shares/:id" element={<Private roles={STAFF}><ShareDetail /></Private>} />
        <Route path="/requests" element={<Private roles={STAFF}><Requests /></Private>} />
        <Route path="/requests/:id" element={<Private roles={STAFF}><RequestDetail /></Private>} />
        <Route path="/vendors" element={<Private roles={STAFF}><Vendors /></Private>} />
        <Route path="/settings/totp" element={<Private roles={STAFF}><TotpSetup /></Private>} />
        <Route path="/settings" element={<Private roles={STAFF}><Settings /></Private>} />
        <Route path="/admin/audit" element={<Private roles={["admin"]}><Audit /></Private>} />
        <Route path="/admin/trace" element={<Private roles={STAFF}><Trace /></Private>} />
        <Route path="/admin/rules" element={<Private roles={["admin"]}><RulesPage /></Private>} />
        <Route path="/admin/users" element={<Private roles={["admin"]}><Users /></Private>} />
        <Route path="/admin/shares" element={<Private roles={["admin"]}><AllShares /></Private>} />
        <Route path="/admin/shares/:id" element={<Private roles={["admin"]}><ShareDetail admin /></Private>} />
        <Route path="/admin/requests/:id" element={<Private roles={["admin"]}><RequestDetail admin /></Private>} />
        <Route path="/vendor/shares" element={<Private roles={VENDOR}><VendorShares /></Private>} />
        <Route path="/vendor/shares/:id" element={<Private roles={VENDOR}><VendorShare /></Private>} />
        <Route path="/vendor/upload" element={<Private roles={VENDOR}><VendorUpload /></Private>} />
        <Route path="/invite/:token" element={<Invite kind="vendor" />} />
        <Route path="/activate/:token" element={<Invite kind="staff" />} />
        <Route path="/s/:token" element={<Access />} />
        <Route path="/r/:token" element={<UploadPage />} />
        <Route path="*" element={<Navigate to="/files" replace />} />
      </Routes>
    </BrowserRouter>
  </StrictMode>,
);
