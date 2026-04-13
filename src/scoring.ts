/**
 * English-likeness scoring for candidate plaintexts.
 * Combines chi-squared on A–Z frequencies, printable ratio, and common bigrams.
 */

const ENGLISH_FREQ: Record<string, number> = {
  A: 0.08167, B: 0.01492, C: 0.02782, D: 0.04253, E: 0.12702, F: 0.02228,
  G: 0.02015, H: 0.06094, I: 0.06966, J: 0.00153, K: 0.00772, L: 0.04025,
  M: 0.02406, N: 0.06749, O: 0.07507, P: 0.01929, Q: 0.00095, R: 0.05987,
  S: 0.06327, T: 0.09056, U: 0.02758, V: 0.00978, W: 0.0236, X: 0.0015,
  Y: 0.01974, Z: 0.00074,
};

/** A–Z expected frequencies in index order (matches χ² loop over ENGLISH_FREQ). */
const ENGLISH_FREQ_ARRAY = new Float64Array(26);
for (let i = 0; i < 26; i++) {
  ENGLISH_FREQ_ARRAY[i] = ENGLISH_FREQ[String.fromCharCode(65 + i)]!;
}

const COMMON_BIGRAMS = new Set([
  "TH", "HE", "IN", "ER", "AN", "RE", "ND", "AT", "ON", "NT", "HA", "ES",
  "ST", "EN", "ED", "TO", "IT", "OU", "EA", "HI", "IS", "OR", "TI", "AS",
  "AR", "SE", "AL", "TE", "VE", "OF", "ME", "BE", "LE", "DE", "RO", "NE",
]);

/** Packed (c1<<8)|c2 for uppercase A–Z bigrams — same membership as COMMON_BIGRAMS. */
const COMMON_BIGRAM_CODES = new Set<number>();
for (const p of COMMON_BIGRAMS) {
  COMMON_BIGRAM_CODES.add((p.charCodeAt(0) << 8) | p.charCodeAt(1));
}

export interface ScoreResult {
  score: number;
  chiSq: number;
  letterRatio: number;
  printableRatio: number;
  bigramBonus: number;
}

function chiSquaredEnglish(upper: string): number {
  const counts = new Uint32Array(26);
  for (let i = 0; i < upper.length; i++) {
    const c = upper.charCodeAt(i);
    if (c >= 65 && c <= 90) counts[c - 65]!++;
  }
  let letters = 0;
  for (let i = 0; i < 26; i++) letters += counts[i]!;
  if (letters < 4) return 1e6;

  let chi = 0;
  for (let i = 0; i < 26; i++) {
    const observed = counts[i]!;
    const expected = ENGLISH_FREQ_ARRAY[i]! * letters;
    const d = observed - expected;
    chi += (d * d) / expected;
  }
  return chi;
}

function bigramScore(upper: string): number {
  let hits = 0;
  const lim = upper.length - 1;
  for (let i = 0; i < lim; i++) {
    const c1 = upper.charCodeAt(i);
    const c2 = upper.charCodeAt(i + 1);
    if (c1 >= 65 && c1 <= 90 && c2 >= 65 && c2 <= 90) {
      if (COMMON_BIGRAM_CODES.has((c1 << 8) | c2)) hits++;
    }
  }
  return hits / Math.max(1, lim);
}

/**
 * Higher is better. Typical readable English: roughly -5 to 15+.
 * Garbage binary: large negative or very negative.
 */
export function scoreEnglish(text: string): ScoreResult {
  if (!text.length) {
    return {
      score: -1e9,
      chiSq: 1e9,
      letterRatio: 0,
      printableRatio: 0,
      bigramBonus: 0,
    };
  }

  let printable = 0;
  let asciiSafe = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if ((c >= 32 && c <= 126) || c === 9 || c === 10 || c === 13) printable++;
    if (c >= 32 && c <= 126) asciiSafe++;
    else if (c === 9 || c === 10 || c === 13) asciiSafe++;
  }
  const printableRatio = printable / text.length;
  const asciiRatio = asciiSafe / text.length;
  // Latin-1 high bytes look "printable" but are not English — penalize heavily
  const asciiPenalty = (1 - asciiRatio) * 80;

  const upper = text.toUpperCase();
  let letterCount = 0;
  for (let i = 0; i < upper.length; i++) {
    const c = upper.charCodeAt(i);
    if (c >= 65 && c <= 90) letterCount++;
  }
  const letterRatio = letterCount / text.length;

  const chiSq = chiSquaredEnglish(upper);
  const bigramBonus = bigramScore(upper) * 50;

  // Lower chi-squared (closer to English distribution) is better → subtract from score
  const score =
    -chiSq * 0.12 -
    asciiPenalty +
    asciiRatio * 45 +
    letterRatio * 35 +
    bigramBonus;

  return {
    score,
    chiSq,
    letterRatio,
    printableRatio: asciiRatio,
    bigramBonus,
  };
}

export function bufferToPrintableUtf8(buf: Buffer): string | null {
  try {
    const s = buf.toString("utf8");
    if (/[\uFFFD]/.test(s)) return null;
    return s;
  } catch {
    return null;
  }
}

export function bufferToLatin1(buf: Buffer): string {
  return buf.toString("latin1");
}
