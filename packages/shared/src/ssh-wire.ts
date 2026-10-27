/**
 * Builds the binary records SSH keys are made of (RFC 4251 §5): big-endian
 * uint32s, length-prefixed strings and mpints. Plain Uint8Array, no Buffer,
 * so the same code runs in the browser and in Node.
 */
export class SshWriter {
  private parts: Uint8Array[] = [];

  uint32(n: number): this {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, n);
    return this.raw(bytes);
  }

  raw(bytes: Uint8Array): this {
    this.parts.push(bytes);
    return this;
  }

  string(value: Uint8Array | string): this {
    const bytes = typeof value === "string" ? new TextEncoder().encode(value) : value;
    return this.uint32(bytes.length).raw(bytes);
  }

  /**
   * A non-negative integer from its big-endian bytes. Leading zeros are
   * dropped, and a 0x00 is added back when the top bit is set — otherwise
   * SSH would read the number as negative.
   */
  mpint(bytes: Uint8Array): this {
    let start = 0;
    while (start < bytes.length && bytes[start] === 0) start++;
    const trimmed = bytes.subarray(start);
    const first = trimmed[0];
    const negative = first !== undefined && (first & 0x80) !== 0;
    return this.string(negative ? concatBytes(new Uint8Array([0]), trimmed) : trimmed);
  }

  bytes(): Uint8Array {
    return concatBytes(...this.parts);
  }
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}
