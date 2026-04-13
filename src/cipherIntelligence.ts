/**
 * Aggregated cryptanalysis: statistics, per-family cipher likelihoods,
 * multi-layer hypotheses, and falsifiable critical notes — complements
 * payloadAnalysis + solver heuristics.
 */

import type { Candidate } from "./solver.js";
import type { PayloadAnalysisReport } from "./payloadAnalysis.js";
import type { HexPatternReport } from "./hexPatterns.js";
import { tryZlibVariants } from "./layerTransforms.js";

const ENGLISH_IOC = 0.065;

export interface CipherTypePrediction {
  id: string;
  label: string;
  /** 0–100 heuristic confidence (not statistical p-value). */
  confidence: number;
  summary: string;
  evidence: string[];
}

export interface LayerHypothesis {
  rank: number;
  /** Human-readable stack, outer → inner. */
  chain: string[];
  confidence: number;
  notes: string;
}

export interface CriticalInsight {
  title: string;
  observation: string;
  interpretation: string;
  falsify: string;
}

export interface CipherIntelligenceStats {
  indexOfCoincidence: number | null;
  letterCountForIoc: number;
  englishExpectedIoc: number;
  byteEntropyBits: number;
  printableAsciiRatio: number;
  zlibInflateLikely: boolean;
  zlibSizeRatio: number | null;
  approxPeriodFromStructure: number | null;
  topSolverMethods: { method: string; count: number }[];
  bestCandidateMethod: string | null;
  bestCandidateScore: number | null;
}

export interface CipherIntelligenceReport {
  predictions: CipherTypePrediction[];
  layerHypotheses: LayerHypothesis[];
  insights: CriticalInsight[];
  stats: CipherIntelligenceStats;
}

function shannonEntropy(buf: Buffer): number {
  if (buf.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < buf.length; i++) counts[buf[i]!]!++;
  let h = 0;
  const n = buf.length;
  for (let b = 0; b < 256; b++) {
    const c = counts[b]!;
    if (c === 0) continue;
    const p = c / n;
    h -= p * Math.log2(p);
  }
  return h;
}

function printableRatio(buf: Buffer): number {
  if (buf.length === 0) return 0;
  let ok = 0;
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i]!;
    if (b === 9 || b === 10 || b === 13 || (b >= 32 && b <= 126)) ok++;
  }
  return ok / buf.length;
}

/** Index of coincidence on A–Z letters only (Latin-1 view of buffer). */
function indexOfCoincidenceBuffer(buf: Buffer): { ioc: number | null; letters: number } {
  const counts = new Uint32Array(26);
  let letters = 0;
  for (let i = 0; i < buf.length; i++) {
    let c = buf[i]!;
    if (c >= 0x61 && c <= 0x7a) c -= 32;
    if (c >= 0x41 && c <= 0x5a) {
      counts[c - 0x41]!++;
      letters++;
    }
  }
  if (letters < 12) return { ioc: null, letters };

  let sum = 0;
  for (let i = 0; i < 26; i++) {
    const n = counts[i]!;
    sum += n * (n - 1);
  }
  const denom = letters * (letters - 1);
  const ioc = denom > 0 ? sum / denom : null;
  return { ioc, letters };
}

function extractPeriodHint(hp: HexPatternReport | undefined): number | null {
  if (!hp?.finds.length) return null;
  for (const f of hp.finds) {
    const m = /period (\d+)/i.exec(f.title);
    if (m) return Number.parseInt(m[1]!, 10);
  }
  return null;
}

function methodHistogram(candidates: Candidate[], topN: number): { method: string; count: number }[] {
  const m = new Map<string, number>();
  for (const c of candidates) {
    m.set(c.method, (m.get(c.method) ?? 0) + 1);
  }
  return [...m.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, topN)
    .map(([method, count]) => ({ method, count }));
}

function clamp01(x: number): number {
  return Math.max(0, Math.min(1, x));
}

/** Map 0–1 signal to 0–100 with soft curve. */
function toConfidence(t: number): number {
  return Math.round(100 * clamp01(t));
}

/**
 * Build full intelligence report from outer Base64, decoded bytes, payload scan, and candidate pool.
 */
export function buildCipherIntelligence(opts: {
  outerBase64: string;
  decoded: Buffer | null;
  payload: PayloadAnalysisReport | null;
  candidates: Candidate[];
  solved: boolean;
}): CipherIntelligenceReport {
  const { outerBase64, decoded, payload, candidates, solved } = opts;
  const hp: HexPatternReport | undefined = payload?.hexPatterns;

  const entropy = decoded ? shannonEntropy(decoded) : 0;
  const printable = decoded ? printableRatio(decoded) : 0;
  const { ioc, letters: letterCount } = decoded
    ? indexOfCoincidenceBuffer(decoded)
    : { ioc: null, letters: 0 };

  let zlibLikely = false;
  let zlibRatio: number | null = null;
  if (decoded && decoded.length >= 6) {
    const inflated = tryZlibVariants(decoded);
    if (inflated && inflated.length > 0) {
      zlibLikely = true;
      zlibRatio = inflated.length / decoded.length;
    }
  }

  const periodHint = extractPeriodHint(hp);
  const topMethods = methodHistogram(candidates, 10);
  const best = candidates[0];

  const stats: CipherIntelligenceStats = {
    indexOfCoincidence: ioc,
    letterCountForIoc: letterCount,
    englishExpectedIoc: ENGLISH_IOC,
    byteEntropyBits: entropy,
    printableAsciiRatio: printable,
    zlibInflateLikely: zlibLikely,
    zlibSizeRatio: zlibRatio,
    approxPeriodFromStructure: periodHint,
    topSolverMethods: topMethods,
    bestCandidateMethod: best?.method ?? null,
    bestCandidateScore: best !== undefined ? best.score : null,
  };

  const predictions: CipherTypePrediction[] = [];

  // --- Scoring helpers (independent 0–1 signals) ---
  const iocSig =
    ioc === null
      ? 0.35
      : 1 - Math.min(1, Math.abs(ioc - ENGLISH_IOC) / 0.045);
  const lowIocSig =
    ioc === null ? 0.4 : ioc < 0.055 ? 1 - ioc / 0.055 : 0;
  const highEntropySig =
    decoded && decoded.length >= 32
      ? clamp01((entropy - 6.2) / (8 - 6.2))
      : 0;
  const blockAlignedSig =
    decoded && decoded.length >= 16 && decoded.length % 16 === 0 && entropy > 6.4
      ? 0.55 + 0.25 * highEntropySig
      : 0.25;
  const xorHintSig = hp?.xorHints?.[0]?.printableRatio
    ? clamp01((hp.xorHints[0].printableRatio - 0.15) / 0.55)
    : 0;
  const periodicitySig = periodHint !== null && periodHint >= 2 ? 0.65 : 0.25;
  const nestedCount = payload?.matches?.length ?? 0;
  const nestedSig = clamp01(nestedCount / 4 + (outerBase64.length > 80 ? 0.1 : 0));

  const methodBoost = (needle: string) => {
    const row = topMethods.find((t) => t.method.includes(needle));
    if (!row) return 0;
    return clamp01(row.count / Math.max(20, candidates.length * 0.15));
  };

  // 1) Transport / encoding chain
  predictions.push({
    id: "encoding-chain",
    label: "Encoding / armoring (Base64, hex, PEM, JWT, …)",
    confidence: toConfidence(
      0.55 + 0.35 * nestedSig + (zlibLikely ? 0.15 : 0),
    ),
    summary:
      nestedCount > 0
        ? "Nested or alternate ASCII armoring is likely — unwrap before treating bytes as ciphertext."
        : "Outer ciphertext is Base64-shaped; inner format may still be text armoring or raw binary.",
    evidence: [
      `Outer string length ${outerBase64.length} (Base64 transport).`,
      nestedCount
        ? `${nestedCount} nested-format match(es) in decoded payload scan.`
        : "No extra PEM/JWT/hex wrapper flags — inner may be opaque binary.",
      zlibLikely
        ? `zlib/gzip-style inflate succeeded (size ratio ${zlibRatio?.toFixed(2) ?? "?"}) — compression or DEFLATE-wrapped payload is plausible.`
        : "No successful zlib inflate on raw decoded buffer (may still be compressed with different framing).",
    ],
  });

  // 2) Classical monoalphabetic
  predictions.push({
    id: "monoalphabetic",
    label: "Monoalphabetic substitution / Caesar family",
    confidence: toConfidence(
      0.35 * iocSig +
        0.25 * clamp01(printable - 0.5) +
        0.2 * (1 - highEntropySig) +
        0.2 * methodBoost("b64-rotate") +
        0.15 * methodBoost("atbash"),
    ),
    summary:
      ioc !== null && Math.abs(ioc - ENGLISH_IOC) < 0.018
        ? "Letter IOC is near English — consistent with simple substitution on letters if interpreted as text."
        : "IOC is not strongly English-like on raw bytes (may be binary layer first).",
    evidence: [
      ioc !== null
        ? `IOC ≈ ${ioc.toFixed(4)} (English ~${ENGLISH_IOC}) on ${letterCount} letters.`
        : "Too few A–Z letters in raw buffer for IOC — need a text-producing layer first.",
      `Printable ASCII ratio ${(printable * 100).toFixed(1)}%.`,
    ],
  });

  // 3) Polyalphabetic (Vigenère / Beaufort on text or Base64)
  predictions.push({
    id: "polyalphabetic",
    label: "Polyalphabetic (Vigenère / Beaufort / repeating key on alphabet)",
    confidence: toConfidence(
      0.3 * lowIocSig +
        0.35 * periodicitySig +
        0.25 * methodBoost("vigenere") +
        0.25 * methodBoost("beaufort") +
        0.15 * (periodHint !== null ? 0.8 : 0),
    ),
    summary:
      periodHint
        ? `Structural period ~${periodHint} suggests repeating-key family if ciphertext is not block-aligned noise.`
        : "Low IOC or solver hits on Vigenère/Beaufort paths support polyalphabetic hypotheses.",
    evidence: [
      ioc !== null
        ? `IOC ${ioc.toFixed(4)} ${ioc < 0.055 ? "(suppressed vs English)" : "(not strongly polyalphabetic alone)"}.`
        : "IOC unavailable on this buffer.",
      periodHint
        ? `Hex/pattern scan suggests byte period ${periodHint}.`
        : "No strong periodicity flag in structural scan.",
      `Solver pool includes Vigenère/Beaufort attempts: ${topMethods.some((m) => m.method.includes("vigenere") || m.method.includes("beaufort")) ? "yes (see best methods)" : "present in pipeline"}.`,
    ],
  });

  // 4) Repeating XOR / OTP-like stream on bytes
  predictions.push({
    id: "xor-stream",
    label: "Repeating XOR / additive stream on raw bytes",
    confidence: toConfidence(
      0.35 * xorHintSig +
        0.3 * methodBoost("xor-repeat") +
        0.25 * methodBoost("xor-1byte") +
        0.25 * periodicitySig +
        0.15 * (entropy > 5.5 && entropy < 7.8 ? 0.6 : 0.2),
    ),
    summary:
      xorHintSig > 0.45
        ? "Single-byte XOR strongly improves printability — multi-byte XOR keys are already brute-forced in the solver."
        : "XOR remains a standard first break for game payloads; scores in candidate pool reflect tries.",
    evidence: [
      hp?.xorHints?.[0]
        ? `Best 1-byte XOR printable ratio ${(hp.xorHints[0].printableRatio * 100).toFixed(1)}% (key 0x${hp.xorHints[0].keyByte.toString(16).padStart(2, "0")}).`
        : "No standout 1-byte XOR printability hint.",
      `Entropy ${entropy.toFixed(2)} bits/byte.`,
    ],
  });

  // 5) RC4 / custom stream
  predictions.push({
    id: "rc4-custom",
    label: "RC4 or custom keystream (keyed PRNG XOR)",
    confidence: toConfidence(
      0.25 * highEntropySig +
        0.35 * methodBoost("layer-rc4") +
        0.2 * methodBoost("rc4") +
        0.2 * (printable < 0.45 ? 0.7 : 0.2),
    ),
    summary:
      "High-entropy binary with flat byte use often matches stream ciphers; solver probes RC4 with keyword-derived keys.",
    evidence: [
      `Byte entropy ${entropy.toFixed(2)}; printable ${(printable * 100).toFixed(1)}%.`,
      topMethods.some((t) => t.method.includes("rc4") || t.method.includes("RC4"))
        ? "RC4-related candidates appear in the pool."
        : "Check layered pipeline for RC4 attempts if keyword list covers passphrase.",
    ],
  });

  // 6) Block cipher (AES family, ECB hints)
  predictions.push({
    id: "block-cipher",
    label: "Block cipher (AES / 3DES / Blowfish-style) or binary token",
    confidence: toConfidence(
      0.45 * highEntropySig +
        0.3 * blockAlignedSig +
        0.35 * methodBoost("block-") +
        (hp?.finds.some((f) => f.title.includes("Repeated 16-byte")) ? 0.2 : 0),
    ),
    summary:
      "Random-looking bytes, optional 16-byte alignment, and duplicate block hints point to block modes or unrelated binary.",
    evidence: [
      decoded
        ? `Length ${decoded.length} bytes${decoded.length % 16 === 0 ? " (multiple of 16)" : ""}.`
        : "No decoded buffer.",
      hp?.finds.some((f) => f.title.includes("16-byte"))
        ? "Repeated 16-byte blocks detected — ECB or structured framing possible."
        : "No repeated 16-byte block highlight.",
      `Extended probes include OpenSSL-style decrypt attempts when enabled.`,
    ],
  });

  // 7b) Alphabet / community transforms (Base64 rot, atbash, string reverse)
  predictions.push({
    id: "alphabet-transforms",
    label: "Alphabet transforms (Base64 rotation, Atbash, reverse)",
    confidence: toConfidence(
      0.35 * methodBoost("b64-rotate") +
        0.3 * methodBoost("atbash") +
        0.25 * methodBoost("reverse") +
        0.15,
    ),
    summary:
      "Community puzzles often permute the Base64 alphabet or reverse strings before standard decode — solver enumerates these.",
    evidence: [
      topMethods.some(
        (t) =>
          t.method.includes("b64-rotate") ||
          t.method.includes("atbash") ||
          t.method.includes("reverse"),
      )
        ? "Some rotate/atbash/reverse candidates appear in the top method counts."
        : "These transforms are always attempted; scores indicate whether they help on this ciphertext.",
    ],
  });

  // 8) Transposition / permutation (weak signal from stats alone)
  predictions.push({
    id: "transposition",
    label: "Transposition / rail-fence / permutation on letters",
    confidence: toConfidence(
      0.25 * iocSig * (1 - lowIocSig) * 0.8 +
        0.15 * methodBoost("classical-rail") +
        0.1 * methodBoost("reverse"),
    ),
    summary:
      "IOC can stay English-like under transposition while digraph statistics differ — rely on solver rail/reverse and dictionary hits.",
    evidence: [
      "Statistical tests here cannot reliably separate transposition from substitution; use quadgram/dictionary scoring already in the tool.",
    ],
  });

  // 9) Compression
  predictions.push({
    id: "compression",
    label: "Compression (DEFLATE / gzip) before or after encryption",
    confidence: toConfidence(zlibLikely ? 0.92 : 0.18 + 0.15 * highEntropySig),
    summary: zlibLikely
      ? "Raw buffer inflates — likely compressed payload; may still be nested inside encryption."
      : "No inflate on first try; payload might use raw DEFLATE or non-zlib compression.",
    evidence: zlibLikely
      ? [`Inflated size ratio ≈ ${zlibRatio?.toFixed(3)}.`]
      : ["gunzip/inflate/inflateRaw did not return on buffer as-is."],
  });

  predictions.sort((a, b) => b.confidence - a.confidence);

  // --- Layer hypotheses ---
  const layerHypotheses: LayerHypothesis[] = [];
  const chainA: string[] = ["Base64 (outer)"];
  if (nestedCount) {
    const kinds = payload!.matches.map((m) => m.kind);
    chainA.push(...kinds.slice(0, 3));
  } else {
    chainA.push("Opaque binary or text (no extra wrapper flags)");
  }
  if (zlibLikely) chainA.push("zlib/gzip-compatible compressed blob");
  if (highEntropySig > 0.55) chainA.push("High-entropy inner (encryption or compressed noise)");

  layerHypotheses.push({
    rank: 1,
    chain: chainA,
    confidence: toConfidence(0.55 + 0.2 * nestedSig + (zlibLikely ? 0.15 : 0)),
    notes:
      "Treat as unwrap order: decode transports first, then attack cryptographic layers on the innermost high-signal buffer.",
  });

  const chainB = [
    "Base64 (outer)",
    "XOR / Vigenère-on-B64 classical layer",
    "English or structured inner",
  ];
  layerHypotheses.push({
    rank: 2,
    chain: chainB,
    confidence: toConfidence(
      0.4 +
        0.2 * methodBoost("xor-repeat") +
        0.2 * (methodBoost("vigenere") + methodBoost("beaufort")) * 0.5,
    ),
    notes:
      "Fits community workflows: transform outer string, then decode Base64 to bytes. Falsified if strict English only appears on unrelated method.",
  });

  const chainC = [
    "Base64 (outer)",
    "Block or stream cipher on decoded bytes",
    "Optional nested Base64 on decrypted result",
  ];
  layerHypotheses.push({
    rank: 3,
    chain: chainC,
    confidence: toConfidence(0.35 + 0.35 * highEntropySig + 0.15 * blockAlignedSig),
    notes:
      "Use when inner entropy is high and classical transforms stall — keyword-derived AES attempts matter.",
  });

  layerHypotheses.sort((a, b) => b.confidence - a.confidence);
  layerHypotheses.forEach((L, i) => {
    L.rank = i + 1;
  });

  // --- Critical insights (falsifiable narrative) ---
  const insights: CriticalInsight[] = [];

  insights.push({
    title: "Heuristic scores vs. true plaintext",
    observation: `Best candidate method “${best?.method ?? "n/a"}” at score ${best?.score.toFixed(2) ?? "n/a"}; pool size ${candidates.length}.`,
    interpretation:
      "High score indicates English-like statistics, not proof. Low spread between top candidates suggests ambiguity or layered noise.",
    falsify:
      "If ground-truth plaintext is known, compare method label — mismatch means missing transform or wrong alphabet.",
  });

  insights.push({
    title: "Index of coincidence on raw decoded bytes",
    observation:
      ioc !== null
        ? `IOC=${ioc.toFixed(4)} from ${letterCount} letters (English ~0.065).`
        : "Too few Latin letters — IOC is misleading until a text layer appears.",
    interpretation:
      ioc !== null && Math.abs(ioc - ENGLISH_IOC) < 0.02
        ? "Consistent with monoalphabetic English if the buffer is letter text."
        : "Binary or polyalphabetic layers suppress or skew IOC on the raw buffer.",
    falsify:
      "Successful decode from a method that yields different letter statistics refutes reliance on raw IOC.",
  });

  insights.push({
    title: "Entropy and randomness",
    observation: `Shannon entropy ${entropy.toFixed(2)} bits/byte; printable ratio ${(printable * 100).toFixed(1)}%.`,
    interpretation:
      entropy > 7.3 && printable < 0.4
        ? "Looks like keyed encryption, compression, or urandom — not ASCII prose."
        : "Moderate entropy may still hide structured text after one transform.",
    falsify:
      "A simple XOR/Vigenère path that jumps to strict English contradicts 'pure high-entropy ciphertext' without ruling out layering.",
  });

  insights.push({
    title: "Solver coverage",
    observation: `Top methods: ${topMethods.slice(0, 5).map((m) => `${m.method}×${m.count}`).join(", ") || "none"}.`,
    interpretation:
      "If the true method uses non-alphanumeric keys, custom base64 alphabets, or extra nesting depth beyond env limits, rankings may miss it.",
    falsify:
      "Manual trial of the actual method should dominate the candidate list once parameters match.",
  });

  insights.push({
    title: "Strict English gate",
    observation: solved
      ? "Run reported SOLVED — strict dictionary + quadgram gate passed."
      : "No strict English — remaining output is best-effort near-miss or noise-shaped.",
    interpretation:
      "Near-misses can look readable in places; rely on the readability card and word scan for false positives.",
    falsify:
      "Human inspection of the alleged solution should read as coherent game narrative, not accidental n-grams.",
  });

  if (periodHint) {
    insights.push({
      title: "Structural period",
      observation: `Pattern scan flagged period ${periodHint} (byte-level repetition heuristic).`,
      interpretation:
        "Supports repeating-key XOR/Vigenère length guesses; could also be format framing.",
      falsify:
        "If brute keys at that length fail and English does not improve, period may be spurious.",
    });
  }

  return { predictions, layerHypotheses, insights, stats };
}

/** Plain text for session log. */
export function formatCipherIntelligenceForLog(report: CipherIntelligenceReport): string {
  const lines: string[] = [];
  const s = report.stats;
  lines.push("");
  lines.push(`# ${"=".repeat(72)}`);
  lines.push("# Cipher intelligence — predictions, layers, critique");
  lines.push(`# ${"=".repeat(72)}`);
  lines.push(
    `IOC: ${s.indexOfCoincidence !== null ? s.indexOfCoincidence.toFixed(4) : "n/a"} (${s.letterCountForIoc} letters)  |  expected English ~${s.englishExpectedIoc}`,
  );
  lines.push(
    `Entropy: ${s.byteEntropyBits.toFixed(2)} b/b  |  printable ASCII: ${(s.printableAsciiRatio * 100).toFixed(1)}%  |  zlib: ${s.zlibInflateLikely ? `yes (ratio ${s.zlibSizeRatio?.toFixed(3)})` : "no"}`,
  );
  if (s.approxPeriodFromStructure) {
    lines.push(`Structural period hint: ${s.approxPeriodFromStructure}`);
  }
  lines.push(`Best candidate: ${s.bestCandidateMethod ?? "n/a"}  score=${s.bestCandidateScore?.toFixed(2) ?? "n/a"}`);
  lines.push("Top solver methods: " + s.topSolverMethods.map((m) => `${m.method}×${m.count}`).join(", "));
  lines.push("");
  lines.push("Cipher-type predictions (sorted):");
  for (const p of report.predictions) {
    lines.push(`  [${p.confidence}%] ${p.label}`);
    lines.push(`    ${p.summary}`);
    for (const e of p.evidence) lines.push(`    · ${e}`);
  }
  lines.push("");
  lines.push("Layer hypotheses:");
  for (const L of report.layerHypotheses) {
    lines.push(`  #${L.rank} (${L.confidence}%): ${L.chain.join(" → ")}`);
    lines.push(`    ${L.notes}`);
  }
  lines.push("");
  lines.push("Critical analysis:");
  for (const i of report.insights) {
    lines.push(`  • ${i.title}`);
    lines.push(`    Obs: ${i.observation}`);
    lines.push(`    → ${i.interpretation}`);
    lines.push(`    Falsify: ${i.falsify}`);
  }
  lines.push("");
  return lines.join("\n");
}
