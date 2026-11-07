import { useCallback, useEffect, useState } from "react";
import { Link, Navigate, useLocation, useParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import Viewer from "../../components/Viewer";
import { errKey } from "../recipient/errKey";
import { api, ApiError, fmtDate, fmtSize, headFile, nav, type RecipientFiles } from "../../api";

// One share's files for a signed-in vendor; same behaviour as the recipient files step, under /api/vendor/shares/{id}.
export default function VendorShare() {
  const { id = "" } = useParams();
  const from = useLocation().pathname;
  const { t, i18n } = useTranslation();
  const [data, setData] = useState<RecipientFiles | null>(null);
  const [err, setErr] = useState("");
  const [viewing, setViewing] = useState("");
  const [pendingNote, setPendingNote] = useState(false);
  const [dlErr, setDlErr] = useState("");
  const base = `/api/vendor/shares/${encodeURIComponent(id)}`;

  const load = useCallback(async () => {
    try {
      const d = await api.vendorShareFiles(id);
      setData(d);
      setErr("");
      return d;
    } catch (e) {
      setData(null);
      setErr(e instanceof ApiError && e.status === 401 ? "login" : errKey(e)); // 401: signed out mid-session
      return null;
    }
  }, [id]);
  useEffect(() => { void load(); }, [load]);

  // re-check access first so a revoked share shows its reason instead of a raw error download
  const download = async (e: React.MouseEvent<HTMLAnchorElement>) => {
    if (e.ctrlKey || e.metaKey || e.shiftKey || e.altKey || e.button !== 0) return; // let the browser open its own tab/window
    e.preventDefault();
    const href = e.currentTarget.getAttribute("href") ?? "";
    const fid = e.currentTarget.dataset.file;
    setPendingNote(false);
    setDlErr("");
    const r = await load();
    if (!r) return;
    if (r.files.find((f) => f.id === fid)?.mark_pending) { setPendingNote(true); return; }
    try { await headFile(href); } catch (x) { setDlErr(errKey(x)); return; }
    nav.go(href);
  };

  if (err === "login") return <Navigate to="/login" replace state={{ from }} />;
  const lng = i18n.language;
  return (
    <>
      <p><Link to="/vendor/shares">{t("vendorPortal.back")}</Link></p>
      {err && <p role="alert">{t(`recipient.error.${err}`)}</p>}
      {data && (
        <>
          <h1>{t("recipient.filesTitle")}</h1>
          {data.message && <blockquote style={{ whiteSpace: "pre-wrap" }}>{data.message}</blockquote>}
          <p>{t("recipient.expires", { at: fmtDate(data.expires_at, lng) })}</p>
          {!data.allow_download && <p>{t("share.viewOnlyNote")}</p>}
          {pendingNote && <p role="alert">{t("share.markPending")}</p>}
          {dlErr && <p role="alert">{t(`recipient.error.${dlErr}`)}</p>}
          {viewing && <Viewer base={`${base}/files/${encodeURIComponent(viewing)}/preview`} onClose={() => setViewing("")} onSessionEnded={() => { setViewing(""); void load(); }} />}
          <table>
            <tbody>
              {data.files.map((f) => (
                <tr key={f.id}>
                  <td>{f.name}</td>
                  <td>{fmtSize(f.size, lng)}</td>
                  <td>
                    {!f.available ? t("recipient.fileUnavailable") : data.download_forbidden && f.previewable === false ? t("recipient.blockedByAdmin") : (
                      <>
                        {f.previewable !== false && <button onClick={() => setViewing(f.id)}>{t("viewer.open")}</button>}{" "}
                          {f.previewable === false && !data.allow_download && t("recipient.noActions")}
                        {data.allow_download && (
                          <a href={`${base}/files/${encodeURIComponent(f.id)}/content`} download data-file={f.id} onClick={download}>{t("files.download")}</a>
                        )}
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </>
  );
}
