"use client";

import { useEffect, useState } from "react";

/**
 * Hook que detecta si la página está siendo servida desde un dominio
 * inesperado (posible phishing). Compara el hostname actual con una
 * lista de dominios permitidos.
 *
 *
 * Si el dominio no coincide, muestra una advertencia crítica.
 */

const ALLOWED_HOSTNAMES = [
  "localhost",
  "127.0.0.1",
  "preview-chat-db9fa2b3-fa0d-4c82-aa60-df9320fb6a68.space-z.ai",
  // Añadir dominios de producción aquí
];

export function usePhishingDetection() {
  const [warning, setWarning] = useState<string | null>(null);

  useEffect(() => {
    const hostname = window.location.hostname;
    let detectedWarning: string | null = null;
    
    // Verificar si el dominio está en la lista de permitidos
    const isAllowed = ALLOWED_HOSTNAMES.some(
      (allowed) => hostname === allowed || hostname.endsWith("." + allowed)
    );

    if (!isAllowed) {
      detectedWarning =
        `ADVERTENCIA: Estás accediendo desde ${hostname}, que no es un dominio oficial. ` +
        "Posible intento de phishing. Verifica la URL antes de introducir tu contraseña maestra.";
    }

    // Verificar protocolo (debe ser HTTPS en producción, excepto localhost)
    if (
      window.location.protocol !== "https:" &&
      hostname !== "localhost" &&
      hostname !== "127.0.0.1"
    ) {
      detectedWarning =
        "ADVERTENCIA: Esta página no usa HTTPS. Tu contraseña maestra podría ser interceptada.";
    }

    // Usar microtask para evitar setState dentro del effect
    if (detectedWarning) {
      Promise.resolve().then(() => setWarning(detectedWarning));
    }
  }, []);

  return { warning };
}
