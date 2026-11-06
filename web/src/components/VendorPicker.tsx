import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, type VendorInfo } from "../api";

// Checkbox list of active vendors with a filter box; `selected` holds vendor ids.
export default function VendorPicker({ selected, onChange }: { selected: string[]; onChange: (ids: string[]) => void }) {
  const { t } = useTranslation();
  const [all, setAll] = useState<VendorInfo[]>([]);
  const [q, setQ] = useState("");
  useEffect(() => {
    api.vendors(true).then((v) => setAll(Array.isArray(v) ? v : []), () => {});
  }, []);
  if (all.length === 0) return null;
  const label = (v: VendorInfo) => `${v.display_name} <${v.email}>${v.org ? ` · ${v.org}` : ""}`;
  const shown = all.filter((v) => label(v).toLowerCase().includes(q.trim().toLowerCase()));
  const toggle = (id: string) => onChange(selected.includes(id) ? selected.filter((x) => x !== id) : [...selected, id]);
  return (
    <fieldset>
      <legend>{t("vendors.pick")}</legend>
      <label>{t("vendors.filter")}
        <input type="search" value={q} onChange={(e) => setQ(e.target.value)} />
      </label>
      {shown.map((v) => (
        <label key={v.id} className="check">
          <input type="checkbox" checked={selected.includes(v.id)} onChange={() => toggle(v.id)} />{label(v)}
        </label>
      ))}
    </fieldset>
  );
}
