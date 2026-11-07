import { useEffect, useState } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { useTranslation } from "react-i18next";
import Shell from "./Shell";
import { api, ApiError } from "../api";

// Loads /api/me: 401 -> /login; a role outside `roles` -> that role's home page.
export default function Private({ roles, children }: { roles: string[]; children: React.ReactNode }) {
  const { t } = useTranslation();
  const [ok, setOk] = useState<boolean | null>(null);
  const [role, setRole] = useState("");
  const from = useLocation().pathname;
  useEffect(() => {
    api.me().then(
      (me) => { setRole(me.role); setOk(true); },
      (e) => setOk(!(e instanceof ApiError && e.status === 401)),
    );
  }, []);
  if (ok === null) return <p>{t("app.loading")}</p>;
  if (!ok) return <Navigate to="/login" replace state={{ from }} />;
  if (role && !roles.includes(role)) return <Navigate to={role === "vendor" ? "/vendor/shares" : "/files"} replace />;
  return <Shell role={role}>{children}</Shell>;
}
