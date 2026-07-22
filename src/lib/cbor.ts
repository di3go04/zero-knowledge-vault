/**
 * Minimal CBOR decoder for WebAuthn structures.
 * Supports: integers, byte strings, text strings, arrays, maps.
 */
export class CborDecoder {
  private view: DataView;
  private buf: ArrayBufferLike;
  private offset: number;

  constructor(buf: ArrayBufferLike) {
    if (buf instanceof SharedArrayBuffer) {
      this.buf = buf.slice(0);
    } else {
      this.buf = buf;
    }
    this.view = new DataView(this.buf);
    this.offset = 0;
  }

  decodeAny(): unknown {
    const initial = this.view.getUint8(this.offset);
    const majorType = initial >> 5;
    const additionalInfo = initial & 0x1f;

    switch (majorType) {
      case 0: return this.decodeUint(additionalInfo);
      case 1: return this.decodeNint(additionalInfo);
      case 2: return this.decodeBytes(additionalInfo);
      case 3: return this.decodeText(additionalInfo);
      case 4: return this.decodeArray(additionalInfo);
      case 5: return this.decodeMap(additionalInfo);
      default: throw new Error(`Unsupported CBOR major type: ${majorType}`);
    }
  }

  private getLength(additionalInfo: number): number {
    if (additionalInfo < 24) return additionalInfo;
    if (additionalInfo === 24) {
      const val = this.view.getUint8(this.offset);
      this.offset++;
      return val;
    }
    if (additionalInfo === 25) {
      const val = this.view.getUint16(this.offset);
      this.offset += 2;
      return val;
    }
    if (additionalInfo === 26) {
      const val = this.view.getUint32(this.offset);
      this.offset += 4;
      return val;
    }
    if (additionalInfo === 27) {
      const hi = this.view.getUint32(this.offset);
      this.offset += 4;
      const lo = this.view.getUint32(this.offset);
      this.offset += 4;
      return hi * 0x100000000 + lo;
    }
    throw new Error(`Unsupported CBOR additional info: ${additionalInfo}`);
  }

  private readHeader(additionalInfo: number): void {
    this.offset++;
  }

  private decodeUint(additionalInfo: number): number {
    this.readHeader(additionalInfo);
    return this.getLength(additionalInfo - 0);
  }

  private decodeNint(additionalInfo: number): number {
    this.readHeader(additionalInfo);
    const val = this.getLength(additionalInfo - 0);
    return -1 - val;
  }

  private decodeBytes(additionalInfo: number): Uint8Array {
    this.readHeader(additionalInfo);
    const len = this.getLength(additionalInfo);
    const bytes = new Uint8Array(this.buf.slice(this.offset, this.offset + len));
    this.offset += len;
    return bytes;
  }

  private decodeText(additionalInfo: number): string {
    this.readHeader(additionalInfo);
    const len = this.getLength(additionalInfo);
    const bytes = new Uint8Array(this.buf, this.offset, len);
    this.offset += len;
    return new TextDecoder().decode(bytes);
  }

  private decodeArray(additionalInfo: number): unknown[] {
    this.readHeader(additionalInfo);
    const len = this.getLength(additionalInfo);
    const arr: unknown[] = [];
    for (let i = 0; i < len; i++) {
      arr.push(this.decodeAny());
    }
    return arr;
  }

  private decodeMap(additionalInfo: number): Record<string, unknown> {
    this.readHeader(additionalInfo);
    const len = this.getLength(additionalInfo);
    const map: Record<string, unknown> = {};
    for (let i = 0; i < len; i++) {
      const key = this.decodeAny();
      const val = this.decodeAny();
      map[String(key)] = val;
    }
    return map;
  }
}
