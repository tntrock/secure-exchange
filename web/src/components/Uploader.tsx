import { useEffect, useRef, useState } from "react";
import { Upload } from "tus-js-client";
import { useTranslation } from "react-i18next";

type Status = "uploading" | "paused" | "done" | "failed";

function UploadItem({ file, onDone }: { file: File; onDone: () => void }) {
  const { t } = useTranslation();
  const up = useRef<Upload | null>(null);
  const [pct, setPct] = useState(0);
  const [status, setStatus] = useState<Status>("uploading");
  const [cancelled, setCancelled] = useState(false);

  useEffect(() => {
    const u = new Upload(file, {
      endpoint: "/api/uploads/",
      chunkSize: 64 * 1024 * 1024,
      retryDelays: [0, 1000, 3000, 5000, 10000],
      metadata: { filename: file.name, filetype: file.type },
      storeFingerprintForResuming: true,
      onProgress: (sent, total) => setPct(total ? Math.floor((sent / total) * 100) : 0),
      onSuccess: () => {
        setPct(100);
        setStatus("done");
        onDone();
      },
      onError: () => setStatus("failed"),
    });
    up.current = u;
    let live = true;
    // Resume a partial upload of the same file (e.g. after a page refresh).
    u.findPreviousUploads().then((prev) => {
      if (!live) return;
      if (prev.length) u.resumeFromPreviousUpload(prev[0]);
      u.start();
    });
    return () => {
      live = false;
      u.abort();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [file]);

  if (cancelled) return null;
  const toggle = () => {
    if (status === "uploading") {
      up.current?.abort();
      setStatus("paused");
    } else if (status === "paused" || status === "failed") {
      up.current?.start();
      setStatus("uploading");
    }
  };
  return (
    <div className="upload">
      <span>{file.name}</span>
      <progress max={100} value={pct} />
      <span>{status === "done" ? t("upload.done") : status === "failed" ? t("upload.failed") : `${pct}%`}</span>
      {status !== "done" && <button onClick={toggle}>{status === "uploading" ? t("upload.pause") : t("upload.resume")}</button>}
      {status !== "done" && (
        <button
          onClick={() => {
            up.current?.abort(true); // also terminates the server-side upload
            setCancelled(true);
          }}
        >
          {t("upload.cancel")}
        </button>
      )}
    </div>
  );
}

export default function Uploader({ onDone }: { onDone: () => void }) {
  const { t } = useTranslation();
  const [files, setFiles] = useState<File[]>([]);
  const [over, setOver] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const add = (list: FileList | null) => list && setFiles((f) => [...f, ...Array.from(list)]);
  return (
    <div>
      <div
        className={"drop" + (over ? " over" : "")}
        onClick={() => input.current?.click()}
        onDragOver={(e) => {
          e.preventDefault();
          setOver(true);
        }}
        onDragLeave={() => setOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setOver(false);
          add(e.dataTransfer.files);
        }}
      >
        {t("upload.drop")}
        <input
          ref={input}
          type="file"
          multiple
          hidden
          onChange={(e) => {
            add(e.target.files);
            e.target.value = "";
          }}
        />
      </div>
      {files.map((f, i) => (
        <UploadItem key={i} file={f} onDone={onDone} />
      ))}
    </div>
  );
}
