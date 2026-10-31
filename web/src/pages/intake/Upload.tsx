import { useCallback, useEffect, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import LangSwitch from "../../components/LangSwitch";
import Uploader from "../../components/Uploader";
import { api, ApiError, fmtDate, fmtSize, type IntakeFiles, type IntakeLanding } from "../../api";

type Step = "loading" | "email" | "code" | "upload" | "fatal";

function errKey(e: unknown) {
  if (e instanceof ApiError) {
    if (e.status === 404) return "notFound";
    if (e.status === 410) return "gone";
    if (e.status === 429) return "rateLimited";
    if (e.status === 401) return e.message === "invalid_code" ? "invalidCode" : "sessionEnded";
  }
  return "generic";
}

// tus 403 bodies
const uploadErr: Record<string, string> = { ext_not_allowed: "extNotAllowed", too_many_files: "tooManyFiles", quota_exceeded: "quotaExceeded" };

const extOf = (name: string) => (name.includes(".") ? name.split(".").pop()!.toLowerCase() : "");

// Same three states as recipient/Access: landing/email -> code -> upload. The token and email live only in memory.
export default function UploadPage() {
  const { token = "" } = useParams();
  const { t, i18n } = useTranslation();
  const [step, setStep] = useState<Step>("loading");
  const [landing, setLanding] = useState<IntakeLanding | null>(null);
  const [data, setData] = useState<IntakeFiles | null>(null);
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [err, setErr] = useState("");
  const [info, setInfo] = useState("");
  const [busy, setBusy] = useState(false);
  // what this page has already handed to the uploader since the last refresh; /files does not count it yet
  const queued = useRef({ n: 0, b: 0 });

  const loadLanding = useCallback(async () => {
    try {
      setLanding(await api.intakeLanding(token));
      return true;
    } catch (e) {
      setErr(errKey(e));
      setStep("fatal");
      return false;
    }
  }, [token]);

  // initial: page load, where 401 just means not signed in yet; otherwise it means the session ended
  const loadFiles = useCallback(async (initial: boolean) => {
    try {
      setData(await api.intakeFiles(token));
      queued.current = { n: 0, b: 0 };
      setErr("");
      setStep("upload");
    } catch (e) {
      const status = e instanceof ApiError ? e.status : 0;
      if (status === 401) {
        setData(null);
        setStep("email");
        if (!initial) setErr("sessionEnded");
      } else if (!initial && status !== 404 && status !== 410) {
        // a transient error must not leave the upload step: that would unmount the Uploader and abort the other uploads
        setErr(errKey(e));
      } else {
        setErr(errKey(e));
        setStep("fatal");
      }
    }
  }, [token]);

  useEffect(() => {
    void (async () => { if (await loadLanding()) await loadFiles(true); })();
  }, [loadLanding, loadFiles]);

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setErr("");
    setInfo("");
    try { await fn(); } catch (e) { setErr(errKey(e)); } finally { setBusy(false); }
  };
  const sendCode = (e: React.FormEvent) => {
    e.preventDefault();
    void run(async () => {
      await api.intakeCode(token, email.trim());
      setCode("");
      setInfo("codeSent");
      setStep("code");
    });
  };
  const resend = () => run(async () => {
    await api.intakeCode(token, email.trim());
    setInfo("codeSent");
  });
  const verify = (e: React.FormEvent) => {
    e.preventDefault();
    void run(async () => {
      await api.intakeVerify(token, email.trim(), code.trim());
      await loadFiles(false);
    });
  };
  const leave = async () => {
    await api.intakeLogout(token).catch(() => {});
    setData(null);
    setCode("");
    setErr("");
    setInfo("");
    setStep("email");
  };

  const exts = landing?.allowed_exts ?? [];
  const check = (f: File) => {
    if (!data) return null;
    const q = queued.current;
    if (exts.length && !exts.includes(extOf(f.name))) return "intake.error.extNotAllowed";
    if (q.n + 1 > data.files_left) return "intake.error.tooManyFiles";
    if (q.b + f.size > data.bytes_left) return "intake.error.quotaExceeded";
    q.n++;
    q.b += f.size;
    return null;
  };
  const onUploadError = (status: number, body: string) => {
    const key = uploadErr[body.trim()];
    if (status === 403 && key) setErr(key);
    else if (status === 401 || status === 410) void loadFiles(false);
  };

  const lng = i18n.language;
  const busyLabel = (s: string) => (busy ? t("app.loading") : s);
  return (
    <>
      <header>
        <strong>{t("app.title")}</strong>
        <span className="spacer" />
        <LangSwitch />
        {step === "upload" && <button onClick={leave}>{t("intake.leave")}</button>}
      </header>
      <main>
        {step === "loading" && <p>{t("app.loading")}</p>}
        {step === "fatal" && <p role="alert">{t(`intake.error.${err}`)}</p>}
        {step !== "loading" && step !== "fatal" && landing && (
          <>
            <h1>{t("intake.title")}</h1>
            <p>{t("intake.from", { name: landing.owner_name })}</p>
            {landing.message && <blockquote style={{ whiteSpace: "pre-wrap" }}>{landing.message}</blockquote>}
            <p>{t("intake.expires", { at: fmtDate(landing.expires_at, lng) })}</p>
          </>
        )}
        {step === "email" && (
          <form onSubmit={sendCode}>
            <label>{t("intake.email")} <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} /></label>
            <button disabled={busy}>{busyLabel(t("intake.sendCode"))}</button>
          </form>
        )}
        {step === "code" && (
          <form onSubmit={verify}>
            <label>
              {t("intake.code")}{" "}
              <input inputMode="numeric" autoComplete="one-time-code" maxLength={6} required value={code} onChange={(e) => setCode(e.target.value)} />
            </label>
            <button disabled={busy}>{busyLabel(t("intake.verify"))}</button>
            <button type="button" disabled={busy} onClick={resend}>{t("intake.resend")}</button>
            <button type="button" disabled={busy} onClick={() => { setStep("email"); setErr(""); setInfo(""); }}>{t("intake.changeEmail")}</button>
          </form>
        )}
        {info && <p role="status">{t(`intake.${info}`)}</p>}
        {step !== "fatal" && err && <p role="alert">{t(`intake.error.${err}`)}</p>}
        {step === "upload" && data && (
          <>
            <ul>
              <li>{t("intake.allowedExts", { exts: exts.length ? exts.join(", ") : t("intake.anyExt") })}</li>
              <li>{t("intake.filesLeft", { count: data.files_left })}</li>
              <li>{t("intake.bytesLeft", { size: fmtSize(data.bytes_left, lng) })}</li>
            </ul>
            <Uploader
              endpoint={`/api/r/${encodeURIComponent(token)}/uploads/`}
              accept={exts.length ? exts.map((e) => `.${e}`).join(",") : undefined}
              check={check}
              onDone={() => void loadFiles(false)}
              onError={onUploadError}
            />
            <h2>{t("intake.yourFiles")}</h2>
            {data.files.length === 0 ? (
              <p>{t("intake.noFiles")}</p>
            ) : (
              <table>
                <tbody>
                  {data.files.map((f) => (
                    <tr key={f.id}><td>{f.name}</td><td>{fmtSize(f.size, lng)}</td><td>{fmtDate(f.created_at, lng)}</td></tr>
                  ))}
                </tbody>
              </table>
            )}
          </>
        )}
      </main>
    </>
  );
}
