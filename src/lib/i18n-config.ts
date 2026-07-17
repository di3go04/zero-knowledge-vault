/**
 * i18n-config.ts — next-intl configuration for the ZK Vault app.
 *
 * This file is consumed by next-intl's plugin and the routing middleware.
 * Import and use in:
 *   - next.config.ts (via createNextIntlPlugin)
 *   - src/middleware.ts (for locale-based routing)
 */

import { locales, defaultLocale } from "./i18n";

export const i18nConfig = {
  locales,
  defaultLocale,
  localeDetection: true,
};

export type I18nConfig = typeof i18nConfig;
