import type { Metadata } from "next";
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
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="es" suppressHydrationWarning>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-background text-foreground`}
      >
        {children}
        <Toaster />
      </body>
    </html>
  );
}
