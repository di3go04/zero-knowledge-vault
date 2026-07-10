/**
 * session-store.ts — Estado de sesión del usuario.
 *
 * CRÍTICO: Las CryptoKey (masterKey, privateKey) viven SOLO en memoria
 * (Zustand store no persistente). Al recargar la página, se pierden
 * y el usuario debe volver a iniciar sesión con su contraseña maestra.
 * Esto garantiza que NUNCA persistimos material criptográfico sensible.
 */
"use client";

import { create } from "zustand";

export interface SessionState {
  userId: string;
  email: string;
  name: string | null;
  publicKeyJwk: JsonWebKey | null;
  // En memoria únicamente:
  masterKey: CryptoKey | null;
  privateKey: CryptoKey | null;
  publicKey: CryptoKey | null;

  login: (data: {
    userId: string;
    email: string;
    name: string | null;
    publicKeyJwk: JsonWebKey;
    masterKey: CryptoKey;
    privateKey: CryptoKey;
    publicKey: CryptoKey;
  }) => void;
  logout: () => void;
}

export const useSession = create<SessionState>((set) => ({
  userId: "",
  email: "",
  name: null,
  publicKeyJwk: null,
  masterKey: null,
  privateKey: null,
  publicKey: null,

  login: (data) =>
    set({
      userId: data.userId,
      email: data.email,
      name: data.name,
      publicKeyJwk: data.publicKeyJwk,
      masterKey: data.masterKey,
      privateKey: data.privateKey,
      publicKey: data.publicKey,
    }),

  logout: () =>
    set({
      userId: "",
      email: "",
      name: null,
      publicKeyJwk: null,
      masterKey: null,
      privateKey: null,
      publicKey: null,
    }),
}));

export const isAuthenticated = (s: SessionState) => !!s.userId && !!s.privateKey;
