export interface Me { id: string; email: string; display_name: string; role: string; totp_enabled: boolean }
export type MarkMethod = "pdf_pages" | "pdf_meta" | "image_visible" | "image_invisible" | "ooxml_meta" | "odf_meta" | "none";
export type ScanStatus = "none" | "pending" | "clean" | "infected" | "skipped" | "error";
export interface FileInfo { id: string; name: string; content_type: string; size: number; sha256: string; created_at: string; preview_status: "pending" | "ready" | "failed" | "unsupported" | "too_large"; preview_kind: string; scan_status: ScanStatus; scan_result: string | null; request_id: string | null; vendor_email: string | null; mark: { watermark: MarkMethod; plain: MarkMethod; degraded: boolean } }

export interface ShareReq {
  file_ids: string[]; emails: string[]; vendor_ids?: string[]; allow_download: boolean; watermark: boolean;
  expires_at: string; max_views: number | null; ip_allow: string[]; message: string;
}
export interface ShareSummary {
  id: string; created_at: string; expires_at: string; revoked: boolean; expired: boolean;
  file_count: number; recipient_count: number; view_count: number; max_views: number | null;
}
export interface Recipient { id: string; email: string; revoked: boolean; vendor?: boolean; first_opened_at: string | null; last_access_at: string | null }
export interface ShareDetailInfo {
  id: string; message: string; allow_download: boolean; watermark: boolean; expires_at: string; max_views: number | null;
  view_count: number; ip_allow: string[]; revoked: boolean; expired: boolean; created_at: string;
  files: { id: string; name: string; size: number; deleted: boolean }[];
  recipients: Recipient[];
  owner_email?: string;
}

export type VendorStatus = "pending" | "rejected" | "disabled" | "expired" | "invited" | "active";
export interface VendorInfo {
  id: string; email: string; display_name: string; org: string; status: VendorStatus;
  expires_at: string; created_by_name: string; created_at: string; can_manage: boolean;
}
export interface VendorReq { email: string; display_name: string; org: string; expires_at: string }

export interface RecipientLanding { owner_name: string; message: string; expires_at: string }
export interface RecipientFiles {
  message: string; expires_at: string; allow_download: boolean; watermark: boolean;
  download_forbidden?: boolean;
  files: { id: string; name: string; size: number; available: boolean; mark_pending?: boolean; previewable?: boolean }[];
}

export interface VendorShareSummary { id: string; owner_name: string; message: string; expires_at: string; file_count: number; allow_download: boolean; watermark: boolean }
export interface VendorTarget { id: string; name: string; email: string }
export interface VendorUploadInfo { id: string; name: string; size: number; recipient_name: string; created_at: string }

export interface UploadRequest {
  id: string; created_at: string; expires_at: string; revoked: boolean; expired: boolean;
  file_count: number; total_bytes: number; max_files: number; max_total_bytes: number; uploader_count: number;
}
export interface UploadRequestDetail extends UploadRequest {
  owner_email?: string;
  url: string; message: string; allowed_exts: string[];
  uploaders: { id: string; email: string; first_opened_at: string | null; last_access_at: string | null }[];
  files: { id: string; name: string; size: number; uploader_email: string; created_at: string; scan_status: ScanStatus; scan_result: string | null; deleted: boolean }[];
}
export interface RequestReq {
  emails: string[]; expires_at: string; max_files: number; max_total_bytes: number; allowed_exts: string[]; message: string;
}
export interface IntakeLanding { owner_name: string; message: string; expires_at: string; max_files: number; max_total_bytes: number; allowed_exts: string[] }
export interface IntakeFiles { files: { id: string; name: string; size: number; created_at: string }[]; files_left: number; bytes_left: number }

export interface Rules {
  force_watermark: boolean; forbid_download: boolean; share_max_days: number; share_default_days: number; retention_days: number;
  max_file_bytes: number; max_share_bytes: number; upload_max_bytes: number; quota_bytes: number;
  domain_block: string[]; domain_allow: string[]; upload_exts: string[]; external_ip_allow: string[];
  force_totp: boolean;
}

export interface TraceHit {
  source: string; via: string; code: string; file_id: string; file_name: string; share_id: string | null;
  owner_email: string; recipient_email: string; ip: string; at: string; method: string;
}
export interface TraceResult { hits: TraceHit[]; analyzed: boolean; sha256?: string }

export type UserRole = "staff" | "admin" | "vendor";
export interface UserInfo {
  id: string; email: string; display_name: string; role: UserRole; auth_source: string; status: string;
  totp_enabled: boolean; last_login_at: string | null; created_at: string;
}
export type UserAction = "disable" | "enable" | "reset-totp" | "reinvite";

export interface AuditRow {
  id: number; at: string; actor_type: string; actor_id: string; actor_label: string; ip: string; user_agent: string;
  action: string; target_type: string; target_id: string; result: string; detail: string;
}
export type AuditQuery = { since?: string; until?: string; actor?: string; action?: string; target?: string; before?: number };
export interface ForwardingStatus { enabled: boolean; pending: number; last_ok_at: string | null; failing_since: string | null; last_error: string | null; alert: boolean }
export interface NotifyPrefs { first_open: boolean; download: boolean; upload: boolean }

export class ApiError extends Error {
  status: number;
  field?: string;
  code?: string;
  fileIds?: string[];
  constructor(status: number, error: string, field?: string, code?: string, fileIds?: string[]) {
    super(error);
    this.status = status;
    this.field = field;
    this.code = code;
    this.fileIds = fileIds;
  }
}

async function call<T>(method: string, url: string, body?: unknown): Promise<T> {
  const form = body instanceof FormData;
  const res = await fetch(url, {
    method,
    credentials: "same-origin",
    headers: body === undefined || form ? undefined : { "Content-Type": "application/json" },
    body: body === undefined || form ? (body as FormData | undefined) : JSON.stringify(body),
  });
  if (!res.ok) {
    const j = await res.json().catch(() => ({}));
    throw new ApiError(res.status, j.error ?? "error", j.field, j.code, j.file_ids);
  }
  return res.status === 204 ? (undefined as T) : res.json();
}

export const api = {
  me: () => call<Me>("GET", "/api/me"),
  login: (email: string, password: string) => call<{ mfa_required: boolean; totp_setup_required?: boolean }>("POST", "/api/auth/login", { email, password }),
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
  addRecipients: (id: string, emails: string[], vendor_ids: string[] = []) => call<Recipient[]>("POST", `/api/shares/${id}/recipients`, { emails, vendor_ids }),
  revokeRecipient: (id: string, rid: string) => call<void>("POST", `/api/shares/${id}/recipients/${rid}/revoke`),
  recipientLanding: (tk: string) => call<RecipientLanding>("GET", `/api/s/${encodeURIComponent(tk)}`),
  recipientCode: (tk: string, email: string) => call<{ sent: boolean }>("POST", `/api/s/${encodeURIComponent(tk)}/code`, { email }),
  recipientVerify: (tk: string, email: string, code: string) => call<void>("POST", `/api/s/${encodeURIComponent(tk)}/verify`, { email, code }),
  recipientFiles: (tk: string) => call<RecipientFiles>("GET", `/api/s/${encodeURIComponent(tk)}/files`),
  requests: () => call<UploadRequest[]>("GET", "/api/requests"),
  request: (id: string) => call<UploadRequestDetail>("GET", `/api/requests/${id}`),
  createRequest: (r: RequestReq) => call<UploadRequestDetail>("POST", "/api/requests", r),
  revokeRequest: (id: string) => call<void>("POST", `/api/requests/${id}/revoke`),
  intakeLanding: (tk: string) => call<IntakeLanding>("GET", `/api/r/${encodeURIComponent(tk)}`),
  intakeCode: (tk: string, email: string) => call<{ sent: boolean }>("POST", `/api/r/${encodeURIComponent(tk)}/code`, { email }),
  intakeVerify: (tk: string, email: string, code: string) => call<IntakeFiles>("POST", `/api/r/${encodeURIComponent(tk)}/verify`, { email, code }),
  intakeFiles: (tk: string) => call<IntakeFiles>("GET", `/api/r/${encodeURIComponent(tk)}/files`),
  intakeLogout: (tk: string) => call<void>("POST", `/api/r/${encodeURIComponent(tk)}/logout`),
  trace: (q: { code: string } | { sha256: string } | File) => {
    if (q instanceof File) {
      const fd = new FormData();
      fd.append("file", q);
      return call<TraceResult>("POST", "/api/admin/trace", fd);
    }
    return call<TraceResult>("POST", "/api/admin/trace", q);
  },
  rules: () => call<Rules>("GET", "/api/rules"),
  saveRules: (r: Rules) => call<{ rules: Rules; affected_shares: number }>("PUT", "/api/admin/rules", r),
  vendors: (activeOnly = false) => call<VendorInfo[]>("GET", activeOnly ? "/api/vendors?active=1" : "/api/vendors"),
  createVendor: (r: VendorReq) => call<VendorInfo>("POST", "/api/vendors", r),
  approveVendor: (id: string) => call<void>("POST", `/api/vendors/${id}/approve`),
  rejectVendor: (id: string) => call<void>("POST", `/api/vendors/${id}/reject`),
  disableVendor: (id: string) => call<void>("POST", `/api/vendors/${id}/disable`),
  enableVendor: (id: string) => call<void>("POST", `/api/vendors/${id}/enable`),
  reinviteVendor: (id: string) => call<void>("POST", `/api/vendors/${id}/reinvite`),
  setVendorExpiry: (id: string, expires_at: string) => call<void>("PATCH", `/api/vendors/${id}`, { expires_at }),
  vendorShares: () => call<VendorShareSummary[]>("GET", "/api/vendor/shares"),
  vendorShareFiles: (id: string) => call<RecipientFiles>("GET", `/api/vendor/shares/${encodeURIComponent(id)}`),
  vendorRecipients: () => call<VendorTarget[]>("GET", "/api/vendor/recipients"),
  vendorUploads: () => call<VendorUploadInfo[]>("GET", "/api/vendor/uploads"),
  inviteInfo: (tk: string) => call<{ email: string; otpauth_url: string }>("GET", `/api/invite/${encodeURIComponent(tk)}`),
  inviteActivate: (tk: string, password: string, code: string) => call<void>("POST", `/api/invite/${encodeURIComponent(tk)}`, { password, code }),
  recipientLogout: (tk: string) => call<void>("POST", `/api/s/${encodeURIComponent(tk)}/logout`),
  adminShares: (q: string, offset: number) => call<(ShareSummary & { owner_email: string })[]>("GET", `/api/admin/shares?q=${encodeURIComponent(q)}&offset=${offset}`),
  adminShare: (id: string) => call<ShareDetailInfo>("GET", `/api/admin/shares/${id}`),
  adminRevokeShare: (id: string) => call<void>("POST", `/api/admin/shares/${id}/revoke`),
  adminRequests: (q: string, offset: number) => call<(UploadRequest & { owner_email: string })[]>("GET", `/api/admin/requests?q=${encodeURIComponent(q)}&offset=${offset}`),
  adminRequest: (id: string) => call<UploadRequestDetail>("GET", `/api/admin/requests/${id}`),
  adminRevokeRequest: (id: string) => call<void>("POST", `/api/admin/requests/${id}/revoke`),
  adminUsers: () => call<UserInfo[]>("GET", "/api/admin/users"),
  adminCreateUser: (email: string, display_name: string, role: string) => call<UserInfo>("POST", "/api/admin/users", { email, display_name, role }),
  adminUserAction: (id: string, a: UserAction) => call<void>("POST", `/api/admin/users/${id}/${a}`),
  adminSetRole: (id: string, role: string) => call<void>("PATCH", `/api/admin/users/${id}`, { role }),
  activateInfo: (tk: string) => call<{ email: string; totp_required: boolean; otpauth_url: string }>("GET", `/api/activate/${encodeURIComponent(tk)}`),
  activate: (tk: string, password: string, code: string) => call<void>("POST", `/api/activate/${encodeURIComponent(tk)}`, { password, code }),
  totpSetupPending: () => call<{ otpauth_url: string }>("POST", "/api/auth/totp/setup"),
  totpEnroll: (code: string) => call<{ mfa_required: boolean }>("POST", "/api/auth/totp/enroll", { code }),
  auditList: (q: AuditQuery) => call<{ entries: AuditRow[]; next_before: number }>("GET", `/api/admin/audit${auditQS(q)}`),
  auditExportURL: (q: AuditQuery) => `/api/admin/audit/export${auditQS({ ...q, before: undefined })}`,
  auditVerify: () => call<{ checked: number; bad_id: number }>("POST", "/api/admin/audit/verify"),
  auditForwarding: () => call<ForwardingStatus>("GET", "/api/admin/audit/forwarding"),
  shareAudit: (id: string, admin: boolean) => call<{ entries: AuditRow[] }>("GET", `/api/${admin ? "admin/" : ""}shares/${encodeURIComponent(id)}/audit`),
  getNotifyPrefs: () => call<NotifyPrefs>("GET", "/api/me/notifications"),
  putNotifyPrefs: (p: NotifyPrefs) => call<void>("PUT", "/api/me/notifications", p),
};


function auditQS(q: AuditQuery): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) if (v) p.set(k, String(v));
  const s = p.toString();
  return s ? `?${s}` : "";
}

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
