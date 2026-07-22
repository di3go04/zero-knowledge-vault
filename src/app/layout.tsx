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
 * Módulo 1 (CSP): se maneja en middleware.ts con nonces dinámicos.
 * Módulo 4 (noindex, nofollow): el vault NO debe ser indexable.
 * translate=no global: evita Google Translate en formularios sensibles.
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
  // CSP se configura dinámicamente en middleware.ts con nonces.
  // Ver src/middleware.ts para la política completa.
  other: {},
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
