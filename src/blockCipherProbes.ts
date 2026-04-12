import { createDecipheriv, createHash, getCiphers } from "node:crypto";
import { reverseBuffer } from "./transforms.js";

const available = new Set(getCiphers());

/** Key derivations mimicking PHP mcrypt / common “password as key” padding. */
function deriveKeyVariants(password: string, byteLen: number): Buffer[] {
  const out: Buffer[] = [];
  const md5 = createHash("md5").update(password, "utf8").digest();
  const sha = createHash("sha256").update(password, "utf8").digest();
  if (byteLen === 8) {
    out.push(Buffer.from(md5.subarray(0, 8)));
    out.push(Buffer.from(sha.subarray(0, 8)));
    const p = Buffer.alloc(8);
    Buffer.from(password, "utf8").copy(p);
    out.push(p);
  } else if (byteLen === 16) {
    out.push(Buffer.from(md5));
    out.push(Buffer.from(sha.subarray(0, 16)));
    const p = Buffer.alloc(16);
    Buffer.from(password, "utf8").copy(p);
    out.push(p);
  } else if (byteLen === 24) {
    out.push(Buffer.concat([md5, sha.subarray(0, 8)]));
    out.push(Buffer.from(sha.subarray(0, 24)));
    const p = Buffer.alloc(24);
    Buffer.from(password, "utf8").copy(p);
    out.push(p);
  } else if (byteLen === 32) {
    out.push(Buffer.from(sha));
    out.push(Buffer.concat([md5, md5]));
  }
  const seen = new Set<string>();
  return out.filter((b) => {
    if (b.length !== byteLen) return false;
    const h = b.toString("hex");
    if (seen.has(h)) return false;
    seen.add(h);
    return true;
  });
}

function ivFor(alg: string): Buffer {
  if (alg.includes("ecb")) return Buffer.alloc(0);
  if (alg.startsWith("aes")) return Buffer.alloc(16, 0);
  return Buffer.alloc(8, 0);
}

function tryDecrypt(alg: string, data: Buffer, key: Buffer): Buffer | null {
  if (data.length < 8) return null;
  try {
    const iv = ivFor(alg);
    const d = createDecipheriv(alg, key, iv);
    d.setAutoPadding(true);
    const plain = Buffer.concat([d.update(data), d.final()]);
    if (plain.length === 0 || plain.length > data.length * 20) return null;
    return plain;
  } catch {
    return null;
  }
}

export interface BlockProbeHit {
  algorithm: string;
  password: string;
  derivation: string;
  plain: Buffer;
}

/**
 * Try OpenSSL block ciphers that appear in community Zombies solves (AES-*, 3DES).
 * RC2 is attempted only if the runtime’s OpenSSL exposes it (often requires legacy provider).
 */
export function probeBlockCiphers(
  ciphertext: Buffer,
  passwords: string[],
  maxHits = 120,
): BlockProbeHit[] {
  const hits: BlockProbeHit[] = [];
  const tried = new Set<string>();

  const algorithms: { name: string; keyBytes: number }[] = [];
  const add = (name: string, kb: number) => {
    if (available.has(name)) algorithms.push({ name, keyBytes: kb });
  };
  add("aes-128-ecb", 16);
  add("aes-192-ecb", 24);
  add("aes-256-ecb", 32);
  add("aes-128-cbc", 16);
  add("aes-192-cbc", 24);
  add("aes-256-cbc", 32);
  add("aes-128-cfb", 16);
  add("aes-256-cfb", 32);
  add("des-ede3-ecb", 24);
  add("des-ede3-cbc", 24);
  add("rc2-ecb", 8);
  add("rc2-cbc", 8);
  add("rc2-cfb", 8);
  if (available.has("bf-ecb")) algorithms.push({ name: "bf-ecb", keyBytes: 16 });
  if (available.has("bf-cbc")) algorithms.push({ name: "bf-cbc", keyBytes: 16 });

  for (const { name, keyBytes } of algorithms) {
    for (const pw of passwords) {
      const keys = deriveKeyVariants(pw, keyBytes);
      for (let ki = 0; ki < keys.length; ki++) {
        const key = keys[ki]!;
        const sig = `${name}|${pw}|${ki}`;
        if (tried.has(sig)) continue;
        tried.add(sig);
        const plain = tryDecrypt(name, ciphertext, key);
        if (!plain) continue;
        hits.push({
          algorithm: name,
          password: pw,
          derivation: `deriv#${ki + 1}`,
          plain,
        });
        if (hits.length >= maxHits) return hits;
      }
    }
  }
  return hits;
}

/** Same probes with ciphertext bytes reversed first (common final-layer trick in Zombies ciphers). */
export function probeBlockCiphersReversedInput(
  decoded: Buffer,
  passwords: string[],
  maxHits = 120,
): BlockProbeHit[] {
  const rev = reverseBuffer(decoded);
  const inner = probeBlockCiphers(rev, passwords, maxHits);
  return inner.map((h) => ({
    ...h,
    algorithm: `reversed-input->${h.algorithm}`,
  }));
}
