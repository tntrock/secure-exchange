export interface Me { id: string; email: string; display_name: string; role: string; totp_enabled: boolean }
export interface FileInfo { id: string; name: string; content_type: string; size: number; sha256: string; created_at: string; preview_status: "pending" | "ready" | "failed" | "unsupported" | "too_large"; preview_kind: string }

export interface ShareReq {
  file_ids: string[]; emails: string[]; allow_download: boolean; watermark: boolean;
  expires_at: string; max_views: number | null; ip_allow: string[]; message: string;
}
export interface ShareSummary {
  id: string; created_at: string; expires_at: string; revoked: boolean; expired: boolean;
  file_count: number; recipient_count: number; view_count: number; max_views: number | null;
}
export interface Recipient { id: string; email: string; revoked: boolean; first_opened_at: string | null; last_access_at: string | null }
export interface ShareDetailInfo {
  id: string; message: string; allow_download: boolean; watermark: boolean; expires_at: string; max_views: number | null;
  view_count: number; ip_allow: string[]; revoked: boolean; expired: boolean; created_at: string;
  files: { id: string; name: string; size: number; deleted: boolean }[];
  recipients: Recipient[];
}

export interface RecipientLanding { owner_name: string; message: string; expires_at: string }
export interface RecipientFiles {
  message: string; expires_at: string; allow_download: boolean; watermark: boolean;
  files: { id: string; name: string; size: number; available: boolean }[];
}

export class ApiError extends Error {
  status: number;
  field?: string;
  code?: string;
  constructor(status: number, error: string, field?: string, code?: string) {
    super(error);
    this.status = status;
    this.field = field;
    this.code = code;
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
    throw new ApiError(res.status, j.error ?? "error", j.field, j.code);
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
  createShare: (r: ShareReq) => call<{ id: string }>("POST", "/api/shares", r),
  shares: () => call<ShareSummary[]>("GET", "/api/shares"),
  share: (id: string) => call<ShareDetailInfo>("GET", `/api/shares/${id}`),
  revokeShare: (id: string) => call<void>("POST", `/api/shares/${id}/revoke`),
  addRecipients: (id: string, emails: string[]) => call<Recipient[]>("POST", `/api/shares/${id}/recipients`, { emails }),
  revokeRecipient: (id: string, rid: string) => call<void>("POST", `/api/shares/${id}/recipients/${rid}/revoke`),
  recipientLanding: (tk: string) => call<RecipientLanding>("GET", `/api/s/${encodeURIComponent(tk)}`),
  recipientCode: (tk: string, email: string) => call<{ sent: boolean }>("POST", `/api/s/${encodeURIComponent(tk)}/code`, { email }),
  recipientVerify: (tk: string, email: string, code: string) => call<void>("POST", `/api/s/${encodeURIComponent(tk)}/verify`, { email, code }),
  recipientFiles: (tk: string) => call<RecipientFiles>("GET", `/api/s/${encodeURIComponent(tk)}/files`),
  recipientLogout: (tk: string) => call<void>("POST", `/api/s/${encodeURIComponent(tk)}/logout`),
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

// full-page navigation, behind an object so tests can stub it (jsdom's location.assign is not spyable)
export const nav = { go: (href: string) => window.location.assign(href) };
