import { useEffect, useRef, useState } from "react";
import { Upload, type DetailedError } from "tus-js-client";
import { useTranslation } from "react-i18next";

type Status = "uploading" | "paused" | "done" | "failed";

type OnError = (status: number, body: string) => void;

// tus-js-client's default (not exported) plus 429, so a rate-limited create or chunk is retried with retryDelays:
// retry unless the response is a 4xx other than 409/423/429, and only while online.
const shouldRetry = (err: DetailedError) => {
  const status = err.originalResponse?.getStatus() ?? 0;
  return (status < 400 || status >= 500 || [409, 423, 429].includes(status)) && (typeof navigator === "undefined" || navigator.onLine !== false);
};

function UploadItem({ file, endpoint, onDone, onError }: { file: File; endpoint: string; onDone: () => void; onError?: OnError }) {
  const { t } = useTranslation();
  const up = useRef<Upload | null>(null);
  const [pct, setPct] = useState(0);
  const [status, setStatus] = useState<Status>("uploading");
  const [cancelled, setCancelled] = useState(false);

  useEffect(() => {
    const u = new Upload(file, {
      endpoint,
      chunkSize: 64 * 1024 * 1024,
      retryDelays: [0, 1000, 3000, 5000, 10000],
      onShouldRetry: shouldRetry,
      metadata: { filename: file.name, filetype: file.type },
      storeFingerprintForResuming: true,
      onProgress: (sent, total) => setPct(total ? Math.floor((sent / total) * 100) : 0),
      onSuccess: () => {
        setPct(100);
        setStatus("done");
        onDone();
      },
      onError: (err) => {
        setStatus("failed");
        const r = (err as DetailedError | undefined)?.originalResponse;
        onError?.(r?.getStatus() ?? 0, r?.getBody() ?? "");
      },
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

type Props = {
  onDone: () => void;
  endpoint?: string;
  accept?: string;
  check?: (f: File) => string | null; // i18n key when the file is rejected before upload
  onError?: OnError;
};

export default function Uploader({ onDone, endpoint = "/api/uploads/", accept, check, onError }: Props) {
  const { t } = useTranslation();
  const [files, setFiles] = useState<File[]>([]);
  const [over, setOver] = useState(false);
  const [rejected, setRejected] = useState<string[]>([]);
  const input = useRef<HTMLInputElement>(null);
  const add = (list: FileList | null) => {
    if (!list) return;
    const ok: File[] = [];
    const bad: string[] = [];
    for (const f of Array.from(list)) {
      const why = check?.(f) ?? null;
      if (why) bad.push(why);
      else ok.push(f);
    }
    setRejected(bad);
    setFiles((cur) => [...cur, ...ok]);
  };
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
          accept={accept}
          hidden
          onChange={(e) => {
            add(e.target.files);
            e.target.value = "";
          }}
        />
      </div>
      {rejected.map((k, i) => <p key={i} className="error" role="alert">{t(k)}</p>)}
      {files.map((f, i) => (
        <UploadItem key={i} file={f} endpoint={endpoint} onDone={onDone} onError={onError} />
      ))}
    </div>
  );
}
