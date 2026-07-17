export function zeroBuffer(buf: Uint8Array | ArrayBuffer): void {
  if (buf instanceof ArrayBuffer) {
    new Uint8Array(buf).fill(0);
  } else {
    buf.fill(0);
  }
}

export function clearCryptoKeyRef(ref: { current: CryptoKey | undefined }): void {
  ref.current = undefined;
}

export function clearKeyPairRef(ref: { current: CryptoKeyPair | undefined }): void {
  ref.current = undefined;
}
