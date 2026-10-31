import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { api, fmtDate, fmtSize, type FileInfo } from "../api";
import Uploader from "../components/Uploader";
import ShareDialog from "../components/ShareDialog";
import Viewer from "../components/Viewer";
import ScanBadge from "../components/ScanBadge";

// only these may be downloaded, viewed or shared; pending/infected/error are held back by the server too
const usable = (f: FileInfo) => f.scan_status === "none" || f.scan_status === "clean" || f.scan_status === "skipped";

export default function Files() {
  const { t, i18n } = useTranslation();
  const [files, setFiles] = useState<FileInfo[]>([]);
  const [err, setErr] = useState("");
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [dlg, setDlg] = useState(false);
  const [viewing, setViewing] = useState("");
  const toggle = (id: string) => setSel((s) => { const n = new Set(s); if (!n.delete(id)) n.add(id); return n; });

  const refresh = useCallback(() => {
    api.files().then((f) => setFiles(f ?? []), () => setErr(t("app.error")));
  }, [t]);
  useEffect(refresh, [refresh]);
  const anyPending = files.some((f) => f.preview_status === "pending" || f.scan_status === "pending");
  useEffect(() => {
    if (!anyPending) return;
    const id = setInterval(refresh, 5000);
    return () => clearInterval(id);
  }, [anyPending, refresh]);

  const del = async (f: FileInfo) => {
    if (!confirm(t("files.confirmDelete", { name: f.name }))) return;
    try {
      await api.deleteFile(f.id);
      refresh();
    } catch {
      setErr(t("app.error"));
    }
  };

  return (
    <>
      <h1>{t("files.title")}</h1>
      <p><Link to="/settings/totp">{t("files.settings")}</Link></p>
      <Uploader onDone={refresh} />
      {sel.size > 0 && <p><button onClick={() => setDlg(true)}>{t("share.create")} ({t("share.selected", { count: sel.size })})</button></p>}
      {dlg && <ShareDialog fileIds={[...sel]} files={files.filter((f) => sel.has(f.id))} notReady={files.some((f) => sel.has(f.id) && f.preview_status !== "ready")} onClose={() => setDlg(false)} />}
      {viewing && <Viewer base={`/api/files/${viewing}/preview`} onClose={() => setViewing("")} />}
      {err && <p className="error" role="alert">{err}</p>}
      {files.length === 0 ? (
        <p>{t("files.empty")}</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th />
              <th>{t("files.name")}</th>
              <th>{t("files.size")}</th>
              <th>{t("files.created")}</th>
              <th>{t("files.sha256")}</th>
              <th>{t("files.preview.label")}</th>
              <th>{t("scan.label")}</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {files.map((f) => (
              <tr key={f.id}>
                <td><input type="checkbox" aria-label={f.name} checked={sel.has(f.id)} disabled={!usable(f)} onChange={() => toggle(f.id)} /></td>
                <td>{f.name}</td>
                <td>{fmtSize(f.size, i18n.language)}</td>
                <td>{fmtDate(f.created_at, i18n.language)}</td>
                <td><code>{f.sha256.slice(0, 12)}</code></td>
                <td>{t(`files.preview.${f.preview_status}`)}</td>
                <td>{f.request_id && <ScanBadge status={f.scan_status} result={f.scan_result} />}</td>
                <td>
                  {f.preview_status === "ready" && <><button disabled={!usable(f)} onClick={() => setViewing(f.id)}>{t("viewer.open")}</button>{" "}</>}
                  {usable(f) ? <a href={`/api/files/${f.id}/content`} download>{t("files.download")}</a> : <span aria-disabled="true">{t("files.download")}</span>}{" "}
                  <button onClick={() => del(f)}>{t("files.delete")}</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
