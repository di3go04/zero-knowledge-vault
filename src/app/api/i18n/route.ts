import { NextRequest, NextResponse } from "next/server";

const translations: Record<string, Record<string, string>> = {
  en: { "vault.title": "Vault", "vault.new": "New Secret", "vault.share": "Share", "vault.decrypt": "Decrypt" },
  es: { "vault.title": "Bóveda", "vault.new": "Nuevo Secreto", "vault.share": "Compartir", "vault.decrypt": "Descifrar" },
  fr: { "vault.title": "Coffre", "vault.new": "Nouveau Secret", "vault.share": "Partager", "vault.decrypt": "Déchiffrer" },
  de: { "vault.title": "Tresor", "vault.new": "Neues Geheimnis", "vault.share": "Teilen", "vault.decrypt": "Entschlüsseln" },
};

export async function GET(req: NextRequest) {
  const lang = req.nextUrl.searchParams.get("lang") || "en";
  return NextResponse.json({ lang, translations: translations[lang] || translations.en });
}
