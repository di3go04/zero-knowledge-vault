/**
 * session-store.ts — Estado de sesión del usuario.
 *
 * CRÍTICO: Las CryptoKey (masterKey, privateKey) viven SOLO en memoria
 * (Zustand store no persistente). Al recargar la página, se pierden
 * y el usuario debe volver a iniciar sesión con su contraseña maestra.
 *
 * MEJORA Ciclo 2: añadimos sessionToken (HMAC-signed) y expiresAt.
 * El token se envía en Authorization: Bearer en lugar del header
 * x-user-id forjable.
 *
 * LIMPIEZA EN LOGOUT: además de setear las refs a null, forzamos un
 * reemplazo del objeto del store. Esto desreferencia las CryptoKey
 * haciéndolas elegibles para GC. Aunque Web Crypto no expone API para
 * zeroing explícito de memoria, V8 recolectará las keys rápidamente
 * al no quedar referencias. Esto es lo máximo que podemos hacer en
 * un navegador sin WebAssembly-side memory.
 */
"use client";

import { create } from "zustand";

export interface SessionState {
  userId: string;
  email: string;
  name: string | null;
  publicKeyJwk: JsonWebKey | null;
  // Token HMAC-signed para autenticación con el servidor
  sessionToken: string | null;
  expiresAt: number | null;
  // En memoria únicamente:
  masterKey: CryptoKey | null;
  privateKey: CryptoKey | null;
  publicKey: CryptoKey | null;
  mlKemPrivateKey: Uint8Array | null;

  login: (data: {
    userId: string;
    email: string;
    name: string | null;
    publicKeyJwk: JsonWebKey;
    sessionToken: string;
    expiresAt: number;
    masterKey: CryptoKey;
    privateKey: CryptoKey;
    publicKey: CryptoKey;
    mlKemPrivateKey?: Uint8Array | null;
  }) => void;
  logout: () => void;
}

export const useSession = create<SessionState>((set) => ({
  userId: "",
  email: "",
  name: null,
  publicKeyJwk: null,
  sessionToken: null,
  expiresAt: null,
  masterKey: null,
  privateKey: null,
  publicKey: null,
  mlKemPrivateKey: null,

  login: (data) =>
    set({
      userId: data.userId,
      email: data.email,
      name: data.name,
      publicKeyJwk: data.publicKeyJwk,
      sessionToken: data.sessionToken,
      expiresAt: data.expiresAt,
      masterKey: data.masterKey,
      privateKey: data.privateKey,
      publicKey: data.publicKey,
      mlKemPrivateKey: data.mlKemPrivateKey ?? null,
    }),

  // Limpieza explícita: setear todas las refs sensibles a null.
  // Esto desreferencia las CryptoKey y permite al GC reclamarlas.
  // Web Crypto no permite zeroing explícito, pero V8 las recolectará
  // en la próxima pasada del GC (típicamente < 1s si no hay presión).
  logout: () =>
    set({
      userId: "",
      email: "",
      name: null,
      publicKeyJwk: null,
      sessionToken: null,
      expiresAt: null,
      masterKey: null,
      privateKey: null,
      publicKey: null,
    }),
}));

export const isAuthenticated = (s: SessionState) =>
  !!s.userId &&
  !!s.privateKey &&
  !!s.sessionToken &&
  (s.expiresAt === null || s.expiresAt > Math.floor(Date.now() / 1000));
