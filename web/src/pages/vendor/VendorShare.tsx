import { useCallback, useEffect, useState } from "react";
import { Link, Navigate, useParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import Viewer from "../../components/Viewer";
import { api, ApiError, fmtDate, fmtSize, nav, type RecipientFiles } from "../../api";

// recipient.error.* key for a failed load
function errKey(e: unknown) {
  if (e instanceof ApiError) {
    if (e.status === 401) return "login"; // signed out mid-session
    if (e.status === 404) return "notFound";
    if (e.status === 410) return "gone";
    if (e.status === 403) return e.message === "view_limit" ? "viewLimit" : "ipDenied";
  }
  return "generic";
}

// One share's files for a signed-in vendor; same behaviour as the recipient files step, under /api/vendor/shares/{id}.
export default function VendorShare() {
  const { id = "" } = useParams();
  const { t, i18n } = useTranslation();
  const [data, setData] = useState<RecipientFiles | null>(null);
  const [err, setErr] = useState("");
  const [viewing, setViewing] = useState("");
  const [pendingNote, setPendingNote] = useState(false);
  const base = `/api/vendor/shares/${encodeURIComponent(id)}`;

  const load = useCallback(async () => {
    try {
      const d = await api.vendorShareFiles(id);
      setData(d);
      setErr("");
      return d;
    } catch (e) {
      setData(null);
      setErr(errKey(e));
      return null;
    }
  }, [id]);
  useEffect(() => { void load(); }, [load]);

  // re-check access first so a revoked share shows its reason instead of a raw error download
  const download = async (e: React.MouseEvent<HTMLAnchorElement>) => {
    e.preventDefault();
    const href = e.currentTarget.getAttribute("href") ?? "";
    const fid = e.currentTarget.dataset.file;
    setPendingNote(false);
    const r = await load();
    if (!r) return;
    if (r.files.find((f) => f.id === fid)?.mark_pending) setPendingNote(true);
    else nav.go(href);
  };

  if (err === "login") return <Navigate to="/login" replace />;
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
          {viewing && <Viewer base={`${base}/files/${encodeURIComponent(viewing)}/preview`} onClose={() => setViewing("")} onSessionEnded={() => { setViewing(""); void load(); }} />}
          <table>
            <tbody>
              {data.files.map((f) => (
                <tr key={f.id}>
                  <td>{f.name}</td>
                  <td>{fmtSize(f.size, lng)}</td>
                  <td>
                    {!f.available ? t("recipient.fileUnavailable") : (
                      <>
                        <button onClick={() => setViewing(f.id)}>{t("viewer.open")}</button>{" "}
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
