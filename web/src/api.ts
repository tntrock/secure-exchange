export interface Me { id: string; email: string; display_name: string; role: string; totp_enabled: boolean }
export interface FileInfo { id: string; name: string; content_type: string; size: number; sha256: string; created_at: string }

export class ApiError extends Error {
  status: number;
  constructor(status: number, code: string) {
    super(code);
    this.status = status;
  }
}

async function call<T>(method: string, url: string, body?: unknown): Promise<T> {
  const res = await fetch(url, {
    method,
    credentials: "same-origin",
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    const j = await res.json().catch(() => ({}));
    throw new ApiError(res.status, j.error ?? "error");
  }
  return res.status === 204 ? (undefined as T) : res.json();
}

export const api = {
  me: () => call<Me>("GET", "/api/me"),
  login: (email: string, password: string) => call<{ mfa_required: boolean }>("POST", "/api/auth/login", { email, password }),
  totp: (code: string) => call<void>("POST", "/api/auth/totp", { code }),
  logout: () => call<void>("POST", "/api/auth/logout"),
  totpSetup: () => call<{ otpauth_url: string }>("POST", "/api/me/totp/setup"),
  totpEnable: (code: string) => call<void>("POST", "/api/me/totp/enable", { code }),
  files: () => call<FileInfo[]>("GET", "/api/files"),
  deleteFile: (id: string) => call<void>("DELETE", `/api/files/${id}`),
};

export const fmtSize = (n: number, lng: string) => {
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) {
    n /= 1024;
    i++;
  }
  return `${new Intl.NumberFormat(lng, { maximumFractionDigits: i ? 1 : 0 }).format(n)} ${u[i]}`;
};

export const fmtDate = (s: string, lng: string) =>
  new Intl.DateTimeFormat(lng, { dateStyle: "medium", timeStyle: "short" }).format(new Date(s));
