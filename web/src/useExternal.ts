import { useEffect, useState } from "react";
import { api } from "./api";

// true once /api/me says the account is not local (domain accounts have no TOTP of their own); null while loading
export function useExternal(): boolean | null {
  const [ext, setExt] = useState<boolean | null>(null);
  useEffect(() => { api.me().then((m) => setExt(!!m?.auth_source && m.auth_source !== "local"), () => setExt(false)); }, []);
  return ext;
}
