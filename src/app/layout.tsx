import type { Metadata, Viewport } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Toaster } from "@/components/ui/toaster";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

/**
 * Módulo 4 (noindex, nofollow): el vault NO debe ser indexable por
 * buscadores. Esto evita que aparezca en Google/Bing y reduzca la
 * superficie de exposición pública del producto.
 *
 * Módulo 1 (CSP estricta): Content-Security-Policy que bloquea:
 *  - inline scripts (solo nonces)
 *  - inline styles (Next.js los necesita → 'unsafe-inline' para styles)
 *  - eval (forbidden)
 *  - frame-ancestors 'none' (anti-clickjacking)
 *  - connect-src solo a self (no exfiltración a dominios externos)
 *  - form-action solo a self
 */
export const metadata: Metadata = {
  title: "Zero-Knowledge Vault — Gestor de Contraseñas para Equipos",
  description:
    "Gestor de contraseñas Zero-Knowledge con cifrado end-to-end en el navegador. AES-256-GCM, Argon2id, RSA-OAEP, ECDH. El servidor nunca ve tus secretos.",
  keywords: [
    "zero-knowledge",
    "password manager",
    "encryption",
    "AES-256-GCM",
    "Argon2id",
    "Web Crypto API",
    "ECDH",
    "security",
  ],
  authors: [{ name: "ZK Vault Team" }],
  icons: {
    icon: "/logo.svg",
  },
  // Módulo 4: NUNCA indexar la bóveda — contenido sensible y privado.
  robots: {
    index: false,
    follow: false,
    nocache: true,
    googleBot: {
      index: false,
      follow: false,
      noimageindex: true,
      "max-video-preview": -1,
      "max-image-preview": "none",
      "max-snippet": -1,
    },
  },
  openGraph: {
    title: "Zero-Knowledge Vault",
    description:
      "Gestor de contraseñas Zero-Knowledge con cifrado end-to-end en el navegador.",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "Zero-Knowledge Vault",
    description:
      "Gestor de contraseñas Zero-Knowledge con cifrado end-to-end en el navegador.",
  },
  // Módulo 1: Content-Security-Policy estricta como meta tag.
  // Los headers HTTP en next.config.ts son la fuente de verdad, pero el
  // meta tag refuerza la política en rendered HTML.
  other: {
    "content-security-policy": [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob:",
      "font-src 'self' data:",
      "connect-src 'self' https://api.github.com",
      "frame-ancestors 'none'",
      "form-action 'self'",
      "base-uri 'self'",
      "object-src 'none'",
    ].join("; "),
  },
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#0a0e1a" },
    { media: "(prefers-color-scheme: dark)", color: "#0a0e1a" },
  ],
  width: "device-width",
  initialScale: 1,
  maximumScale: 5,
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="es" suppressHydrationWarning translate="no">
      <head>
        {/* Módulo 1: translate=no global — evita que Google Translate
            intervenga con formularios de credenciales y exponga data
            a terceros. */}
        <meta name="google" content="notranslate" />
      </head>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-background text-foreground`}
      >
        {children}
        <Toaster />
      </body>
    </html>
  );
}
