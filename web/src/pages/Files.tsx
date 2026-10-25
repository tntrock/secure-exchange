import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { api, fmtDate, fmtSize, type FileInfo } from "../api";
import Uploader from "../components/Uploader";
import ShareDialog from "../components/ShareDialog";

export default function Files() {
  const { t, i18n } = useTranslation();
  const [files, setFiles] = useState<FileInfo[]>([]);
  const [err, setErr] = useState("");
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [dlg, setDlg] = useState(false);
  const toggle = (id: string) => setSel((s) => { const n = new Set(s); if (!n.delete(id)) n.add(id); return n; });

  const refresh = useCallback(() => {
    api.files().then((f) => setFiles(f ?? []), () => setErr(t("app.error")));
  }, [t]);
  useEffect(refresh, [refresh]);

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
      {dlg && <ShareDialog fileIds={[...sel]} onClose={() => setDlg(false)} />}
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
              <th />
            </tr>
          </thead>
          <tbody>
            {files.map((f) => (
              <tr key={f.id}>
                <td><input type="checkbox" aria-label={f.name} checked={sel.has(f.id)} onChange={() => toggle(f.id)} /></td>
                <td>{f.name}</td>
                <td>{fmtSize(f.size, i18n.language)}</td>
                <td>{fmtDate(f.created_at, i18n.language)}</td>
                <td><code>{f.sha256.slice(0, 12)}</code></td>
                <td>
                  <a href={`/api/files/${f.id}/content`} download>{t("files.download")}</a>{" "}
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
