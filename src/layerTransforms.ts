import { createHash } from "node:crypto";
import { gunzipSync, inflateSync, inflateRawSync } from "node:zlib";
import { safeBase64Decode } from "./transforms.js";

/** RC4 keystream XOR (common in games / custom crypto). */
export function rc4Transform(data: Buffer, key: Buffer): Buffer {
  const S = new Uint8Array(256);
  for (let i = 0; i < 256; i++) S[i] = i;
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + S[i]! + key[i % key.length]!) & 255;
    const tmp = S[i]!;
    S[i] = S[j]!;
    S[j] = tmp;
  }
  let i = 0;
  j = 0;
  const out = Buffer.alloc(data.length);
  for (let k = 0; k < data.length; k++) {
    i = (i + 1) & 255;
    j = (j + S[i]!) & 255;
    const tmp = S[i]!;
    S[i] = S[j]!;
    S[j] = tmp;
    const t = (S[i]! + S[j]!) & 255;
    out[k] = data[k]! ^ S[t]!;
  }
  return out;
}

export function tryZlibVariants(buf: Buffer): Buffer | null {
  if (buf.length < 4) return null;
  for (const fn of [gunzipSync, inflateSync, inflateRawSync]) {
    try {
      const r = fn(buf) as Buffer;
      if (r.length > 0 && r.length < buf.length * 50) return r;
    } catch {
      /* next */
    }
  }
  return null;
}

/** Whether buffer looks like a Base64 text payload (second layer). */
export function looksLikeBase64Text(buf: Buffer): boolean {
  if (buf.length < 8) return false;
  const s = buf.toString("ascii");
  if (!/^[A-Za-z0-9+/=\r\n]+$/.test(s)) return false;
  const t = s.replace(/\s/g, "");
  return t.length % 4 !== 1 && t.length >= 8;
}

export interface LayerBuf {
  buf: Buffer;
  /** Human-readable transform chain */
  path: string;
}

/**
 * Unwrap nested Base64 (decode until not b64-like or max depth).
 */
export function collectNestedBase64(
  first: Buffer,
  maxDepth: number,
): LayerBuf[] {
  const out: LayerBuf[] = [{ buf: first, path: "b64[1]" }];
  let cur = first;
  let path = "b64[1]";
  for (let d = 1; d < maxDepth; d++) {
    if (!looksLikeBase64Text(cur)) break;
    const s = cur.toString("ascii").replace(/\s/g, "");
    const next = safeBase64Decode(s);
    if (!next || next.length === 0) break;
    if (next.equals(cur)) break;
    path = `${path}->b64[${d + 1}]`;
    out.push({ buf: next, path });
    cur = next;
  }
  return out;
}

export function tryHexAsciiDecode(buf: Buffer): Buffer | null {
  const s = buf.toString("ascii").trim();
  if (s.length < 4 || s.length % 2 === 1) return null;
  if (!/^[0-9a-fA-F]+$/.test(s)) return null;
  try {
    return Buffer.from(s, "hex");
  } catch {
    return null;
  }
}

export function bufHashShort(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex").slice(0, 16);
}

export function swapNibbles(buf: Buffer): Buffer {
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i]!;
    out[i] = ((b & 0xf) << 4) | (b >> 4);
  }
  return out;
}

export function looksLikeHexAscii(buf: Buffer): boolean {
  const s = buf.toString("ascii").trim();
  return (
    s.length >= 8 &&
    s.length % 2 === 0 &&
    s.length <= buf.length + 2 &&
    /^[0-9a-fA-F]+$/.test(s)
  );
}
