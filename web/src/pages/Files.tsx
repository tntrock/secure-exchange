import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { api, fmtDate, fmtSize, type FileInfo } from "../api";
import Uploader from "../components/Uploader";

export default function Files() {
  const { t, i18n } = useTranslation();
  const [files, setFiles] = useState<FileInfo[]>([]);
  const [err, setErr] = useState("");

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
      {err && <p className="error" role="alert">{err}</p>}
      {files.length === 0 ? (
        <p>{t("files.empty")}</p>
      ) : (
        <table>
          <thead>
            <tr>
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
