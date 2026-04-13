import { createHash } from "node:crypto";

/** Standard Base64 alphabet order (RFC 4648). */
export const B64_CHARS =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const B64_INDEX = new Map<string, number>();
for (let i = 0; i < B64_CHARS.length; i++) B64_INDEX.set(B64_CHARS[i]!, i);

function cleanB64(s: string): string {
  return s.replace(/\s/g, "").replace(/=+$/, "");
}

export function safeBase64Decode(s: string): Buffer | null {
  const t = cleanB64(s);
  if (t.length % 4 === 1) return null;
  try {
    return Buffer.from(t, "base64");
  } catch {
    return null;
  }
}

/** Vigenère decrypt on Base64 alphabet: P = (C - K) mod 64 */
export function vigenereBase64Decrypt(cipherB64: string, key: string): string {
  const c = cleanB64(cipherB64).replace(/[^A-Za-z0-9+/]/g, "");
  if (!key.length) return c;
  let out = "";
  let ki = 0;
  const keyUpper = key;
  for (const ch of c) {
    const ci = B64_INDEX.get(ch);
    if (ci === undefined) continue;
    const kch = keyUpper[ki % keyUpper.length]!;
    const kiVal = B64_INDEX.get(kch);
    if (kiVal === undefined) {
      ki++;
      continue;
    }
    const pi = (ci - kiVal + 64) % 64;
    out += B64_CHARS[pi]!;
    ki++;
  }
  return out;
}

/** Beaufort variant on Base64: P = (K - C) mod 64 */
export function beaufortBase64Decrypt(cipherB64: string, key: string): string {
  const c = cleanB64(cipherB64).replace(/[^A-Za-z0-9+/]/g, "");
  if (!key.length) return c;
  let out = "";
  let ki = 0;
  for (const ch of c) {
    const ci = B64_INDEX.get(ch);
    if (ci === undefined) continue;
    const kch = key[ki % key.length]!;
    const kiVal = B64_INDEX.get(kch);
    if (kiVal === undefined) {
      ki++;
      continue;
    }
    const pi = (kiVal - ci + 64) % 64;
    out += B64_CHARS[pi]!;
    ki++;
  }
  return out;
}

/** Atbash on Base64 alphabet: index i → 63 − i */
export function atbashBase64(cipherB64: string): string {
  const c = cleanB64(cipherB64);
  let out = "";
  for (const ch of c) {
    const ci = B64_INDEX.get(ch);
    if (ci === undefined) {
      out += ch;
      continue;
    }
    out += B64_CHARS[63 - ci]!;
  }
  return out;
}

export function rotateBase64Alphabet(cipherB64: string, r: number): string {
  const c = cleanB64(cipherB64);
  let out = "";
  for (const ch of c) {
    const ci = B64_INDEX.get(ch);
    if (ci === undefined) {
      out += ch;
      continue;
    }
    out += B64_CHARS[(ci + r + 64) % 64]!;
  }
  return out;
}

export function xorBuffer(buf: Buffer, key: string | Buffer | Uint8Array): Buffer {
  const k =
    typeof key === "string" ? Buffer.from(key, "utf8") : Buffer.from(key);
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) {
    out[i] = buf[i]! ^ k[i % k.length]!;
  }
  return out;
}

export function xorSingleByte(buf: Buffer, b: number): Buffer {
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) out[i] = buf[i]! ^ b;
  return out;
}

export function reverseBuffer(buf: Buffer): Buffer {
  return Buffer.from(buf).reverse();
}

const DEFAULT_KEYS = [
  "TheGiant",
  "thegiant",
  "GIANT",
  "DerRiese",
  "Der Riese",
  "Treyarch",
  "Richtofen",
  "Monty",
  "Shadowman",
  "Agartha",
  "Primis",
  "Ultimis",
  "935",
  "Group935",
  "Maxis",
  "Samantha",
  "Edward",
  "BO3",
  "BlackOps3",
  "zombies",
  "CallOfDuty",
];

const BUILTIN_XOR_KEYS: string[] = [...DEFAULT_KEYS];

export function builtinXorKeys(): string[] {
  return BUILTIN_XOR_KEYS.slice();
}

/** Extra keywords from documented COD Zombies cipher solves (wiki / community). */
const COD_ZOMBIES_CIPHER_KEYWORDS: string[] = [
  "Classified",
  "CLASSIFIED",
  "Pentagon",
  "TheCastle",
  "The Castle",
  "Castle",
  "shinonuma",
  "ShiNoNuma",
  "Testsubjec0074",
  "Testsubject0074",
  "Aurora Borealis",
  "AuroraBorealis",
  "Division9",
  "Division 9",
  "Ascension",
  "Maxis",
  "Edward",
  "Richtofen",
  "Takeo",
  "Masaki",
  "Group935",
  "Group 935",
  "Primis",
  "Ultimis",
  "Apothicon",
  "Keeper",
  "Monty",
  "Shadowman",
];

/**
 * Keywords tied to Treyarch Zombies / Jason Blundell-era cipher hunts (Revelations, The Giant, etc.).
 * Used for classical polyalphabetic probes and block-cipher passphrases (mcrypt-style tooling).
 */
const BLUNDELL_CIPHER_KEYWORDS: string[] = [
  "ZOMBIES",
  "Zombies",
  "zombies",
  "ZOMBIE",
  "Zombie",
  "REVELATIONS",
  "Revelations",
  "revelations",
  "GIANT",
  "TheGiant",
  "The Giant",
  "thegiant",
  "JasonBlundell",
  "Blundell",
  "jasonblundell",
  "Treyarch",
  "treyarch",
  "Primis",
  "Ultimis",
  "Richtofen",
  "Maxis",
  "Samantha",
  "Sophia",
  "Group935",
  "Group 935",
  "Element115",
  "Element 115",
  "115",
  "DerRiese",
  "Der Riese",
  "DerEisendrache",
  "Eisendrache",
  "Origins",
  "Moon",
  "Ascension",
  "Kino",
  "ShiNoNuma",
  "MCrypt",
  "mcrypt",
  "ShadowsOfEvil",
  "SOE",
  "GorodKrovi",
  "Gorod Krovi",
  "Apothicon",
  "Keeper",
  "Aether",
  "SummoningKey",
  "Kronorium",
  "Verruckt",
  "NachtDerUntoten",
  ...COD_ZOMBIES_CIPHER_KEYWORDS,
];

export function codZombiesCipherKeywords(): string[] {
  return COD_ZOMBIES_CIPHER_KEYWORDS.slice();
}

export function blundellCipherKeywords(): string[] {
  return BLUNDELL_CIPHER_KEYWORDS.slice();
}

export function md5Hex(s: string): string {
  return createHash("md5").update(s, "utf8").digest("hex");
}

let cachedDerivedKeys: string[] | undefined;
let cachedDerivedSha256Keys: string[] | undefined;

/** Short keys from hashing common phrases (hex bytes used as XOR key). */
export function derivedKeys(): string[] {
  if (cachedDerivedKeys) return cachedDerivedKeys.slice();
  const seeds = [
    "TheGiant",
    "DerRiese",
    "Group935",
    "Element115",
    "Moon",
  ];
  cachedDerivedKeys = seeds.map((s) => md5Hex(s).slice(0, 16));
  return cachedDerivedKeys.slice();
}

/** SHA256-derived hex keys (16 hex chars = 8 bytes as XOR/RC4 material). */
export function derivedSha256Keys(): string[] {
  if (cachedDerivedSha256Keys) return cachedDerivedSha256Keys.slice();
  const seeds = [
    "TheGiant",
    "DerRiese",
    "Group935",
    "Element115",
    "Moon",
    "ShadowsOfEvil",
    "Origins",
    "MobOfTheDead",
    "Ascension",
    "KinoDerToten",
    "NachtDerUntoten",
    "Verruckt",
    "ShiNoNuma",
    "CallOfTheDead",
    "Buried",
    "TranZit",
    "DieRise",
    "GreenRun",
    "Apothicon",
    "Keeper",
  ];
  cachedDerivedSha256Keys = seeds.map((s) =>
    createHash("sha256").update(s, "utf8").digest("hex").slice(0, 16),
  );
  return cachedDerivedSha256Keys.slice();
}

const EXTRA_STRETCH_KEYS: string[] = [
  "TG",
  "GIANT",
  "giant",
  "TheGiantZombies",
  "TheGiantEE",
  "Robot",
  "GiantRobot",
  "Dragon",
  "Castle",
  "Laboratory",
  "Group 935",
  "Element 115",
  "Element115",
  "115",
  "MPD",
  "Pyramid",
  "Moon",
  "ShangriLa",
  "Alcatraz",
  "Richtofen",
  "Maxis",
  "Samantha",
  "Sophia",
  "Monty",
  "Shadowman",
  "Apothicons",
  "Keepers",
  "SummoningKey",
  "Kronorium",
  "Agartha",
  "Aether",
  "Primis",
  "Ultimis",
  "BO3",
  "BlackOps3",
  "Treyarch",
  "Zombies",
  "CallOfDuty",
  "COD",
  "DerEisendrache",
  "ZetsubouNoShima",
  "Revelations",
  "Shadows",
  "SOE",
];

let cachedAllStretchXorKeys: string[] | undefined;

/**
 * Lore + hash-derived keys for repeating XOR, Vigenère, and layered RC4.
 * Deduplicated; use with `GIANT_EXTRA_KEYS` (env) in the solver.
 */
export function allStretchXorKeys(): string[] {
  if (cachedAllStretchXorKeys) return cachedAllStretchXorKeys.slice();
  const seen = new Set<string>();
  const out: string[] = [];
  for (const k of [
    ...BUILTIN_XOR_KEYS,
    ...derivedKeys(),
    ...derivedSha256Keys(),
    ...EXTRA_STRETCH_KEYS,
  ]) {
    if (!seen.has(k)) {
      seen.add(k);
      out.push(k);
    }
  }
  cachedAllStretchXorKeys = out;
  return out.slice();
}
