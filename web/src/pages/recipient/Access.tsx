import { useCallback, useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import LangSwitch from "../../components/LangSwitch";
import { api, ApiError, fmtDate, fmtSize, nav, type RecipientFiles, type RecipientLanding } from "../../api";

type Step = "loading" | "email" | "code" | "files" | "fatal";

function errKey(e: unknown) {
  if (e instanceof ApiError) {
    if (e.status === 404) return "notFound";
    if (e.status === 410) return "gone";
    if (e.status === 403) return e.message === "view_limit" ? "viewLimit" : "ipDenied";
    if (e.status === 429) return "rateLimited";
    if (e.status === 401) return e.message === "invalid_code" ? "invalidCode" : "sessionEnded";
  }
  return "generic";
}

// Single page, three states: landing/email -> code -> file list. The token and email live only in memory.
export default function Access() {
  const { token = "" } = useParams();
  const { t, i18n } = useTranslation();
  const [step, setStep] = useState<Step>("loading");
  const [landing, setLanding] = useState<RecipientLanding | null>(null);
  const [data, setData] = useState<RecipientFiles | null>(null);
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [err, setErr] = useState("");
  const [info, setInfo] = useState("");
  const [busy, setBusy] = useState(false);

  // reports whether the landing loaded; on failure the fatal reason is already set
  const loadLanding = useCallback(async () => {
    try {
      setLanding(await api.recipientLanding(token));
      setStep("email");
      return true;
    } catch (e) {
      setErr(errKey(e));
      setStep("fatal");
      return false;
    }
  }, [token]);

  // initial: page load (401 = not signed in yet, quietly show landing); otherwise a 401 means the session ended.
  // Reports whether the file list loaded.
  const loadFiles = useCallback(async (initial: boolean) => {
    try {
      setData(await api.recipientFiles(token));
      setStep("files");
      return true;
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        if ((await loadLanding()) && !initial) setErr("sessionEnded");
      } else {
        setErr(errKey(e));
        setStep("fatal");
      }
      return false;
    }
  }, [token, loadLanding]);

  useEffect(() => { void loadFiles(true); }, [loadFiles]);

  // re-check the session first so an ended or revoked one shows its reason instead of a raw error download
  const download = async (e: React.MouseEvent<HTMLAnchorElement>) => {
    e.preventDefault();
    const href = e.currentTarget.getAttribute("href") ?? "";
    if (await loadFiles(false)) nav.go(href);
  };

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setErr("");
    setInfo("");
    try { await fn(); } catch (e) { setErr(errKey(e)); } finally { setBusy(false); }
  };

  const sendCode = (e: React.FormEvent) => {
    e.preventDefault();
    void run(async () => {
      await api.recipientCode(token, email.trim());
      setCode("");
      setInfo("codeSent");
      setStep("code");
    });
  };
  const resend = () => run(async () => {
    await api.recipientCode(token, email.trim());
    setInfo("codeSent");
  });
  const verify = (e: React.FormEvent) => {
    e.preventDefault();
    void run(async () => {
      await api.recipientVerify(token, email.trim(), code.trim());
      await loadFiles(false);
    });
  };
  const leave = async () => {
    await api.recipientLogout(token).catch(() => {});
    setData(null);
    setCode("");
    setErr("");
    setInfo("");
    await loadLanding();
  };

  const lng = i18n.language;
  const busyLabel = (s: string) => (busy ? t("app.loading") : s);
  return (
    <>
      <header>
        <strong>{t("app.title")}</strong>
        <span className="spacer" />
        <LangSwitch />
        {step === "files" && <button onClick={leave}>{t("recipient.leave")}</button>}
      </header>
      <main>
        {step === "loading" && <p>{t("app.loading")}</p>}
        {step === "fatal" && <p role="alert">{t(`recipient.error.${err}`)}</p>}
        {(step === "email" || step === "code") && landing && (
          <>
            <h1>{t("recipient.title")}</h1>
            <p>{t("recipient.from", { name: landing.owner_name })}</p>
            {landing.message && <blockquote style={{ whiteSpace: "pre-wrap" }}>{landing.message}</blockquote>}
            <p>{t("recipient.expires", { at: fmtDate(landing.expires_at, lng) })}</p>
            {step === "email" ? (
              <form onSubmit={sendCode}>
                <label>{t("recipient.email")} <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)} /></label>
                <button disabled={busy}>{busyLabel(t("recipient.sendCode"))}</button>
              </form>
            ) : (
              <form onSubmit={verify}>
                <label>
                  {t("recipient.code")}{" "}
                  <input inputMode="numeric" autoComplete="one-time-code" maxLength={6} required value={code}
                    onChange={(e) => setCode(e.target.value)} />
                </label>
                <button disabled={busy}>{busyLabel(t("recipient.verify"))}</button>
                <button type="button" disabled={busy} onClick={resend}>{t("recipient.resend")}</button>
                <button type="button" disabled={busy} onClick={() => { setStep("email"); setErr(""); setInfo(""); }}>
                  {t("recipient.changeEmail")}
                </button>
              </form>
            )}
            {info && <p role="status">{t(`recipient.${info}`)}</p>}
            {err && <p role="alert">{t(`recipient.error.${err}`)}</p>}
          </>
        )}
        {step === "files" && data && (
          <>
            <h1>{t("recipient.filesTitle")}</h1>
            {data.message && <blockquote style={{ whiteSpace: "pre-wrap" }}>{data.message}</blockquote>}
            <p>{t("recipient.expires", { at: fmtDate(data.expires_at, lng) })}</p>
            {!data.allow_download && <p>{t("share.viewOnlyNote")}</p>}
            <table>
              <tbody>
                {data.files.map((f) => (
                  <tr key={f.id}>
                    <td>{f.name}</td>
                    <td>{fmtSize(f.size, lng)}</td>
                    <td>
                      {!f.available ? t("recipient.fileUnavailable")
                        : data.allow_download && (
                          <a href={`/api/s/${encodeURIComponent(token)}/files/${encodeURIComponent(f.id)}/content`} download onClick={download}>
                            {t("files.download")}
                          </a>
                        )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </main>
    </>
  );
}
