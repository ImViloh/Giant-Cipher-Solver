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

const COMMON_BIGRAMS = new Set([
  "TH", "HE", "IN", "ER", "AN", "RE", "ND", "AT", "ON", "NT", "HA", "ES",
  "ST", "EN", "ED", "TO", "IT", "OU", "EA", "HI", "IS", "OR", "TI", "AS",
  "AR", "SE", "AL", "TE", "VE", "OF", "ME", "BE", "LE", "DE", "RO", "NE",
]);

export interface ScoreResult {
  score: number;
  chiSq: number;
  letterRatio: number;
  printableRatio: number;
  bigramBonus: number;
}

function chiSquaredEnglish(upper: string): number {
  let letters = 0;
  const counts = new Map<string, number>();
  for (const ch of upper) {
    if (ch >= "A" && ch <= "Z") {
      counts.set(ch, (counts.get(ch) ?? 0) + 1);
      letters++;
    }
  }
  if (letters < 4) return 1e6;

  let chi = 0;
  for (const [letter, exp] of Object.entries(ENGLISH_FREQ)) {
    const observed = counts.get(letter) ?? 0;
    const expected = exp * letters;
    const d = observed - expected;
    chi += (d * d) / expected;
  }
  return chi;
}

function bigramScore(upper: string): number {
  let hits = 0;
  for (let i = 0; i < upper.length - 1; i++) {
    const pair = upper.slice(i, i + 2);
    if (COMMON_BIGRAMS.has(pair)) hits++;
  }
  return hits / Math.max(1, upper.length - 1);
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
