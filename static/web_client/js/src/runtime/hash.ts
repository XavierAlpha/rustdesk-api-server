const encoder = new TextEncoder();

export function utf8ToBytes(value: string): Uint8Array {
  return encoder.encode(value);
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const stable = new Uint8Array(data.length);
  stable.set(data);
  const digest = await crypto.subtle.digest('SHA-256', stable);
  return new Uint8Array(digest);
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
