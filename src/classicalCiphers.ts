/**
 * Classical polyalphabetic / transposition ciphers on text.
 * Revelations-style solves often use Beaufort + keyword (e.g. ZOMBIES) with A–Z then a–z as one alphabet.
 */

const A26 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const A52 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

function idx26(ch: string): number | null {
  const u = ch.toUpperCase();
  const i = A26.indexOf(u);
  return i >= 0 ? i : null;
}

function idx52(ch: string): number | null {
  const i = A52.indexOf(ch);
  return i >= 0 ? i : null;
}

function onlyKeyLetters26(key: string): string {
  return key
    .split("")
    .filter((c) => idx26(c) !== null)
    .join("");
}

function onlyKeyLetters52(key: string): string {
  return key
    .split("")
    .filter((c) => idx52(c) !== null)
    .join("");
}

/** Standard Vigenère decrypt A–Z: P = (C − K) mod 26. */
export function vigenereDecryptA26(cipher: string, key: string): string {
  const k = onlyKeyLetters26(key);
  if (!k.length) return cipher;
  let ki = 0;
  let out = "";
  for (const ch of cipher) {
    const ci = idx26(ch);
    if (ci === null) {
      out += ch;
      continue;
    }
    const kv = idx26(k[ki % k.length]!)!;
    const pi = (ci - kv + 26) % 26;
    const upper = ch === ch.toUpperCase();
    const letter = A26[pi]!;
    out += upper ? letter : letter.toLowerCase();
    ki++;
  }
  return out;
}

/** Beaufort A–Z: P = (K − C) mod 26 (same family as community “Beaufort” on BO3 ciphers). */
export function beaufortDecryptA26(cipher: string, key: string): string {
  const k = onlyKeyLetters26(key);
  if (!k.length) return cipher;
  let ki = 0;
  let out = "";
  for (const ch of cipher) {
    const ci = idx26(ch);
    if (ci === null) {
      out += ch;
      continue;
    }
    const kv = idx26(k[ki % k.length]!)!;
    const pi = (kv - ci + 26) % 26;
    const upper = ch === ch.toUpperCase();
    const letter = A26[pi]!;
    out += upper ? letter : letter.toLowerCase();
    ki++;
  }
  return out;
}

/** 52-letter alphabet A–Z then a–z (common in Zombies Revelations–style tooling). */
export function vigenereDecryptA52(cipher: string, key: string): string {
  const k = onlyKeyLetters52(key);
  if (!k.length) return cipher;
  let ki = 0;
  let out = "";
  for (const ch of cipher) {
    const ci = idx52(ch);
    if (ci === null) {
      out += ch;
      continue;
    }
    const kv = idx52(k[ki % k.length]!)!;
    const pi = (ci - kv + 52) % 52;
    out += A52[pi]!;
    ki++;
  }
  return out;
}

export function beaufortDecryptA52(cipher: string, key: string): string {
  const k = onlyKeyLetters52(key);
  if (!k.length) return cipher;
  let ki = 0;
  let out = "";
  for (const ch of cipher) {
    const ci = idx52(ch);
    if (ci === null) {
      out += ch;
      continue;
    }
    const kv = idx52(k[ki % k.length]!)!;
    const pi = (kv - ci + 52) % 52;
    out += A52[pi]!;
    ki++;
  }
  return out;
}

export function atbashLettersA26(text: string): string {
  let out = "";
  for (const ch of text) {
    const i = idx26(ch);
    if (i === null) {
      out += ch;
      continue;
    }
    const pi = 25 - i;
    const upper = ch === ch.toUpperCase();
    const letter = A26[pi]!;
    out += upper ? letter : letter.toLowerCase();
  }
  return out;
}

/** Caesar on A–Z / a–z only. */
export function caesarDecryptA26(text: string, shift: number): string {
  const s = ((shift % 26) + 26) % 26;
  let out = "";
  for (const ch of text) {
    const i = idx26(ch);
    if (i === null) {
      out += ch;
      continue;
    }
    const pi = (i - s + 26) % 26;
    const upper = ch === ch.toUpperCase();
    const letter = A26[pi]!;
    out += upper ? letter : letter.toLowerCase();
  }
  return out;
}

/** ROT13 convenience. */
export function rot13A26(text: string): string {
  return caesarDecryptA26(text, 13);
}

/**
 * Rail fence decode: ciphertext was produced by reading the zigzag row-by-row.
 */
export function railFenceDecode(ciphertext: string, numRails: number): string {
  const clean = ciphertext.replace(/\s/g, "");
  const len = clean.length;
  if (numRails < 2 || len < numRails) return ciphertext;
  const fence: (string | null)[][] = Array.from({ length: numRails }, () =>
    new Array<string | null>(len).fill(null),
  );
  let rail = 0;
  let direction = 1;
  for (let i = 0; i < len; i++) {
    fence[rail]![i] = "*";
    rail += direction;
    if (rail === 0 || rail === numRails - 1) direction *= -1;
  }
  let idx = 0;
  for (let r = 0; r < numRails; r++) {
    for (let i = 0; i < len; i++) {
      if (fence[r]![i] === "*") fence[r]![i] = clean[idx++]!;
    }
  }
  rail = 0;
  direction = 1;
  let result = "";
  for (let i = 0; i < len; i++) {
    result += fence[rail]![i]!;
    rail += direction;
    if (rail === 0 || rail === numRails - 1) direction *= -1;
  }
  return result;
}
