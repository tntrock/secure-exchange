import { ApiError } from "../../api";

// recipient.error.* key for a failed recipient/vendor request or download preflight
export function errKey(e: unknown): string {
  if (!(e instanceof ApiError)) return "generic";
  const m = e.message;
  switch (e.status) {
    case 404: return "notFound";
    case 410: return "gone";
    case 429: return "rateLimited";
    case 401: return m === "invalid_code" ? "invalidCode" : "sessionEnded";
    case 409: case 423: return "scanPending";
    case 403:
      return ({ view_limit: "viewLimit", domain_blocked: "domain_blocked", unmarkable: "unmarkable", view_only: "viewOnly",
        quarantined: "quarantined", scan_failed: "scanFailed", forbidden: "generic" } as Record<string, string>)[m] ?? "ipDenied";
  }
  return "generic";
}
