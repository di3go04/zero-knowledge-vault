/**
 * i18n.ts — Internationalization system for 15 languages.
 *
 * Uses next-intl as the runtime. This file provides:
 *   1. Translation loader (dynamic import per locale)
 *   2. Language configuration (15 languages)
 *   3. Utility types for type-safe translations
 *   4. Locale detection and switching helpers
 *
 * Supported locales:
 *   es (Spanish)      — default
 *   en (English)
 *   fr (French)
 *   de (German)
 *   it (Italian)
 *   pt (Portuguese)
 *   nl (Dutch)
 *   pl (Polish)
 *   ru (Russian)
 *   ja (Japanese)
 *   ko (Korean)
 *   zh (Chinese Simplified)
 *   ar (Arabic)
 *   hi (Hindi)
 *   tr (Turkish)
 */

import { createSharedPathnamesNavigation } from "next-intl/navigation";

export const locales = [
  "es",
  "en",
  "fr",
  "de",
  "it",
  "pt",
  "nl",
  "pl",
  "ru",
  "ja",
  "ko",
  "zh",
  "ar",
  "hi",
  "tr",
] as const;

export type Locale = (typeof locales)[number];

export const defaultLocale: Locale = "es";

export const localeLabels: Record<Locale, string> = {
  es: "Español",
  en: "English",
  fr: "Français",
  de: "Deutsch",
  it: "Italiano",
  pt: "Português",
  nl: "Nederlands",
  pl: "Polski",
  ru: "Русский",
  ja: "日本語",
  ko: "한국어",
  zh: "简体中文",
  ar: "العربية",
  hi: "हिन्दी",
  tr: "Türkçe",
};

// next-intl navigation helpers (used in client components)
export const { Link, redirect, usePathname, useRouter } =
  createSharedPathnamesNavigation({ locales });

/**
 * Dynamic translation loader for next-intl.
 * Usage in `next-intl.config.ts`:
 * ```ts
 * import { getRequestConfig } from "next-intl/server";
 * import { loadMessages } from "@/lib/i18n";
 *
 * export default getRequestConfig(async ({ locale }) => ({
 *   messages: await loadMessages(locale),
 * }));
 * ```
 */
export async function loadMessages(locale: string): Promise<Record<string, unknown>> {
  try {
    return (await import(`@/messages/${locale}.json`)).default;
  } catch {
    console.warn(`[i18n] No messages found for locale "${locale}", falling back to es`);
    return (await import(`@/messages/es.json`)).default;
  }
}

/**
 * Detects the user's preferred locale from the browser.
 * Falls back to the default locale if none match.
 */
export function detectLocale(): Locale {
  if (typeof navigator === "undefined") return defaultLocale;

  const preferred = navigator.language.split("-")[0].toLowerCase() as Locale;
  if (locales.includes(preferred)) return preferred;

  return defaultLocale;
}

/**
 * Returns the direction for a given locale (for RTL support).
 */
export function getLocaleDirection(locale: Locale): "ltr" | "rtl" {
  return locale === "ar" ? "rtl" : "ltr";
}
