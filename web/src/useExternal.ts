import { useEffect, useState } from "react";
import { api } from "./api";

// true once /api/me says the account is not local (domain accounts have no TOTP of their own)
export function useExternal(): boolean {
  const [ext, setExt] = useState(false);
  useEffect(() => { api.me().then((m) => setExt(!!m?.auth_source && m.auth_source !== "local"), () => {}); }, []);
  return ext;
}
