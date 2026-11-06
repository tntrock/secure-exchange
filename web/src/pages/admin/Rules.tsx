import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError, type Rules } from "../../api";

const MiB = 1048576;
const BOOLS = ["force_watermark", "forbid_download"] as const;
const DAYS = ["share_max_days", "share_default_days", "retention_days"] as const;
const SIZES = ["max_file_bytes", "max_share_bytes", "upload_max_bytes", "quota_bytes"] as const;
const LISTS = ["domain_block", "domain_allow", "upload_exts", "external_ip_allow"] as const;
const SECTIONS: { title: string; keys: readonly (keyof Rules)[] }[] = [
  { title: "sharing", keys: ["force_watermark", "forbid_download", "share_max_days", "share_default_days", "max_share_bytes"] },
  { title: "recipients", keys: ["domain_block", "domain_allow", "external_ip_allow"] },
  { title: "external", keys: ["upload_exts", "upload_max_bytes"] },
  { title: "storage", keys: ["max_file_bytes", "quota_bytes", "retention_days"] },
];
const split = (s: string) => s.split("\n").map((x) => x.trim()).filter(Boolean);

// Form state is all strings; converted to the Rules shape (MiB -> bytes, lines -> arrays) on save.
export default function RulesPage() {
  const { t, i18n } = useTranslation();
  const [f, setF] = useState<Record<string, string | boolean> | null>(null);
  const [err, setErr] = useState<{ field: string; msg: string } | null>(null);
  const [affected, setAffected] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);

  const load = (r: Rules) => {
    const s: Record<string, string | boolean> = {};
    for (const k of BOOLS) s[k] = r[k];
    for (const k of DAYS) s[k] = String(r[k]);
    for (const k of SIZES) s[k] = String(r[k] / MiB);
    for (const k of LISTS) s[k] = (r[k] ?? []).join("\n");
    setF(s);
  };
  useEffect(() => { api.rules().then(load, () => setErr({ field: "", msg: t("app.error") })); }, [t]);

  const submit = async (ev: React.FormEvent) => {
    ev.preventDefault();
    if (!f) return;
    setErr(null);
    setAffected(null);
    setBusy(true);
    const body: Record<string, unknown> = {};
    for (const k of BOOLS) body[k] = f[k];
    for (const k of DAYS) body[k] = Number(f[k]);
    for (const k of SIZES) body[k] = Math.round(Number(f[k]) * MiB);
    for (const k of LISTS) body[k] = split(f[k] as string);
    try {
      const r = await api.saveRules(body as unknown as Rules);
      load(r.rules);
      setAffected(r.affected_shares);
    } catch (e) {
      const key = e instanceof ApiError && e.status === 422 ? `rules.error.${e.field}.${e.code}` : "";
      const known = key !== "" && i18n.exists(key);
      setErr({ field: known ? (e as ApiError).field ?? "" : "", msg: t(known ? key : "rules.error.generic") });
    } finally {
      setBusy(false);
    }
  };
  if (!f) return err ? <p className="error" role="alert">{err.msg}</p> : <p>{t("app.loading")}</p>;

  const set = (k: string, v: string | boolean) => setF({ ...f, [k]: v });
  const field = (k: keyof Rules) => {
    const msg = err?.field === k && <span className="error" role="alert">{err.msg}</span>;
    if ((BOOLS as readonly string[]).includes(k))
      return <div key={k}><label className="check"><input type="checkbox" checked={f[k] as boolean} onChange={(e) => set(k, e.target.checked)} />{t(`rules.${k}`)}</label>{msg}</div>;
    if ((LISTS as readonly string[]).includes(k))
      return <div key={k}><label>{t(`rules.${k}`)}<textarea rows={3} value={f[k] as string} onChange={(e) => set(k, e.target.value)} /></label>{k === "external_ip_allow" && <p role="note">{t("rules.ipHint")}</p>}{msg}</div>;
    return <div key={k}><label>{t(`rules.${k}`)}<input type="number" min={0} step="any" value={f[k] as string} onChange={(e) => set(k, e.target.value)} /></label>{msg}</div>;
  };

  return (
    <>
      <h1>{t("rules.title")}</h1>
      <form onSubmit={submit}>
        {err && !err.field && <p className="error" role="alert">{err.msg}</p>}
        {SECTIONS.map((s) => <fieldset key={s.title}><legend>{t(`rules.section.${s.title}`)}</legend>{s.keys.map(field)}</fieldset>)}
        <button disabled={busy}>{t("rules.save")}</button>
        {affected !== null && <p role="status">{t("rules.saved")} {t("rules.affected", { n: affected })}</p>}
      </form>
    </>
  );
}
