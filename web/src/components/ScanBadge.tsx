import { useTranslation } from "react-i18next";
import type { ScanStatus } from "../api";

// "none" (not scanned, e.g. staff uploads) shows nothing.
export default function ScanBadge({ status, result }: { status: ScanStatus; result?: string | null }) {
  const { t } = useTranslation();
  if (status === "none") return null;
  return <span className={`scan ${status}`}>{t(`scan.${status}`)}{status === "infected" && result ? ` (${result})` : ""}</span>;
}
