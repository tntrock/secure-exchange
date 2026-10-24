import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import zhTW from "./zh-TW.json";
import en from "./en.json";

const KEY = "sx_lang";

function initial(): string {
  try {
    const s = localStorage.getItem(KEY);
    if (s === "zh-TW" || s === "en") return s;
  } catch {
    /* storage unavailable */
  }
  return navigator.language.toLowerCase().startsWith("en") ? "en" : "zh-TW";
}

i18n.use(initReactI18next).init({
  resources: { "zh-TW": { translation: zhTW }, en: { translation: en } },
  lng: initial(),
  fallbackLng: "zh-TW",
  interpolation: { escapeValue: false },
});

export function setLanguage(lng: string) {
  try {
    localStorage.setItem(KEY, lng);
  } catch {
    /* ignore */
  }
  document.documentElement.lang = lng;
  return i18n.changeLanguage(lng);
}

export default i18n;
