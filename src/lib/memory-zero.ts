/**
 * =====================================================================
 * memory-zero.ts — Utilidades para limpieza criptográfica de memoria.
 * =====================================================================
 *
 * REGLA: las llaves privadas, secretos compartidos, llaves maestras y
 * cualquier material intermedio (ArrayBuffer, Uint8Array) deben ser
 * sobrescritos con ceros tan pronto como dejen de usarse, especialmente
 * al cerrar diálogos UI.
 *
 * LIMITACIONES:
 *   - Web Crypto NO permite zeroing de CryptoKey. La única forma de
 *     "borrar" una CryptoKey es desreferenciarla (setear la ref a null)
 *     y esperar al GC. Esta utilidad hace lo máximo posible.
 *   - Los strings en JS son inmutables y el GC los recolecta cuando no
 *     hay refs. No se pueden sobrescribir. Para mnemonics y secretos
 *     en claro, usamos Uint8Array cuando es posible.
 *
 * MEJORA Módulo 1: zeroing real de ArrayBuffers temporales.
 * =====================================================================
 */

/**
 * Sobrescribe un ArrayBuffer o Uint8Array con ceros.
 * Usar tan pronto como el buffer deje de ser necesario.
 *
 * @example
 * const rawKey = await exportAesKeyRaw(aesKey);
 * // ... usar rawKey ...
 * zeroBuffer(rawKey); // sobrescribe con ceros
 */
export function zeroBuffer(buf: ArrayBuffer | Uint8Array | null | undefined): void {
  if (!buf) return;
  try {
    const view = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    // Sobrescribir con ceros (no con random — queremos borrar, no ofuscar)
    view.fill(0);
    // Para mayor seguridad, sobrescribir también con patrón alternativo
    // (técnica estándar para evitar optimizaciones del compilador que
    // podrían eliminar el fill(0) por considerar el buffer "dead code").
    view.fill(0xff);
    view.fill(0);
  } catch {
    // Si el buffer fue detached (transferido a Worker), no se puede escribir
  }
}

/**
 * Limpia un CryptoKey del store de React.
 * Como Web Crypto no permite zeroing, desreferenciamos y forzamos GC
 * si está disponible (V8/Chrome exponen `gc()` solo en flags de debug).
 */
export function clearCryptoKeyRef(
  ref: React.MutableRefObject<CryptoKey | null>,
): void {
  ref.current = null;
  // Intentar forzar GC si está disponible (solo en builds de debug)
  if (typeof (globalThis as any).gc === "function") {
    try {
      (globalThis as any).gc();
    } catch {
      // no-op
    }
  }
}

/**
 * Limpia un par de llaves (CryptoKeyPair) del store de React.
 */
export function clearKeyPairRef(
  ref: React.MutableRefObject<CryptoKeyPair | null>,
): void {
  if (ref.current) {
    // Desreferenciar ambas llaves
    ref.current.privateKey = null as unknown as CryptoKey;
    ref.current.publicKey = null as unknown as CryptoKey;
    ref.current = null;
  }
  if (typeof (globalThis as any).gc === "function") {
    try {
      (globalThis as any).gc();
    } catch {
      // no-op
    }
  }
}

/**
 * Sobrescribe un string sensible en memoria convirtiéndolo a Uint8Array,
 * zeroing el buffer, y reemplazando el string original.
 *
 * NOTA: JS strings son inmutables, así que esto NO sobrescribe el string
 * original en el heap. Solo funciona si el string se derivó de un buffer
 * que aún controlamos. Para máxima seguridad, evitar strings para
 * material sensible y usar Uint8Array directamente cuando sea posible.
 */
export function zeroString(str: string): void {
  // Esta función es un placeholder — en JS no se puede zeroing de strings.
  // La incluimos por documentación: el llamador debe usar Uint8Array
  // para material sensible, no strings.
  void str;
}
