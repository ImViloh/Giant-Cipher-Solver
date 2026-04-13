import {
  looksLikeBase64Text,
  looksLikeHexAscii,
} from "./layerTransforms.js";
import { safeBase64Decode } from "./transforms.js";
import {
  analyzeHexPatterns,
  type HexPatternReport,
} from "./hexPatterns.js";

export type { HexPatternReport } from "./hexPatterns.js";

/** One detected wrapper or encoding on top of raw base64 output. */
export interface NestedFormatMatch {
  /** Short label for UI / logs, e.g. "Nested Base64". */
  kind: string;
  /** One-line explanation. */
  description: string;
  /** Truncated sample of what matched (string form). */
  detectedSample: string;
}

export interface ByteFingerprint {
  byteLength: number;
  /** Space-separated hex of first bytes. */
  hexHead: string;
  /** Optional tail hex if buffer is long and might matter. */
  hexTail?: string;
  /** Shannon entropy of the full buffer, bits per byte (0–8). */
  shannonEntropyBits: number;
  /** Ratio of bytes in 0x09,0x0a,0x0d,0x20–0x7e. */
  printableAsciiRatio: number;
  /** Inferred file / container types from magic bytes. */
  magicLabels: string[];
  /** Plain-language guesses (encryption-like vs structured file). */
  inferenceNotes: string[];
}

export interface PayloadAnalysisReport {
  matches: NestedFormatMatch[];
  fingerprint: ByteFingerprint;
  /** Structural hex / XOR / periodicity hints on raw decoded bytes. */
  hexPatterns: HexPatternReport;
}

const SAMPLE_MAX = 220;

function truncateSample(s: string, max = SAMPLE_MAX): string {
  const t = s.replace(/\r\n/g, "↵").replace(/\n/g, "↵").replace(/\r/g, "↵");
  if (t.length <= max) return t;
  return `${t.slice(0, max - 1)}…`;
}

function bufferToScanString(buf: Buffer): { ascii: string; utf8: string | null } {
  const ascii = buf.toString("latin1");
  let utf8: string | null = null;
  try {
    const u = buf.toString("utf8");
    const back = Buffer.from(u, "utf8");
    if (back.equals(buf)) utf8 = u;
  } catch {
    utf8 = null;
  }
  return { ascii, utf8 };
}

function shannonEntropy(buf: Buffer): number {
  if (buf.length === 0) return 0;
  const counts = new Array<number>(256).fill(0);
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

function hexDumpPrefix(buf: Buffer, bytes: number): string {
  const n = Math.min(buf.length, bytes);
  const parts: string[] = [];
  for (let i = 0; i < n; i++) {
    parts.push(buf[i]!.toString(16).padStart(2, "0"));
  }
  return parts.join(" ");
}

function magicFromBuffer(buf: Buffer): string[] {
  const out: string[] = [];
  if (buf.length < 2) return out;

  if (buf.length >= 8 && buf.subarray(0, 8).equals(Buffer.from("Salted__", "ascii"))) {
    out.push("OpenSSL salted format (EVP_BytesToKey) — password-derived key + IV prefix");
  }

  if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) {
    out.push("UTF-8 BOM text");
  }
  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) {
    out.push("UTF-16 LE BOM");
  }
  if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff) {
    out.push("UTF-16 BE BOM");
  }

  if (buf.length >= 4 && buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) {
    out.push("PNG image");
  }
  if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) {
    out.push("JPEG image");
  }
  if (
    buf.length >= 6 &&
    buf[0] === 0x47 &&
    buf[1] === 0x49 &&
    buf[2] === 0x46 &&
    buf[3] === 0x38 &&
    (buf[4] === 0x37 || buf[4] === 0x39) &&
    buf[5] === 0x61
  ) {
    out.push("GIF image");
  }
  if (buf.length >= 4 && buf[0] === 0x25 && buf[1] === 0x50 && buf[2] === 0x44 && buf[3] === 0x46) {
    out.push("PDF document");
  }
  if (buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4b) {
    if (buf[2] === 0x03 && buf[3] === 0x04) out.push("ZIP archive (local file header) / Office Open XML / JAR");
    else if (buf[2] === 0x05 && buf[3] === 0x06) out.push("ZIP end-of-central-directory");
    else if (buf[2] === 0x07 && buf[3] === 0x08) out.push("ZIP / APK signature block nearby");
    else out.push("ZIP family (PK header)");
  }
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
    out.push("gzip compressed stream");
  }
  if (buf.length >= 2 && buf[0] === 0x78 && (buf[1] === 0x9c || buf[1] === 0x01 || buf[1] === 0xda)) {
    out.push("zlib / DEFLATE stream (common compression)");
  }
  if (buf.length >= 2 && buf[0] === 0x42 && buf[1] === 0x4d) {
    out.push("BMP bitmap");
  }
  if (
    buf.length >= 16 &&
    buf.subarray(0, 15).equals(Buffer.from("SQLite format 3", "ascii")) &&
    buf[15] === 0x00
  ) {
    out.push("SQLite database");
  }
  if (buf.length >= 4 && buf[0] === 0x7b && buf[1] !== 0x00) {
    const head = buf.subarray(0, Math.min(64, buf.length)).toString("utf8");
    if (/^\{\s*"/.test(head) || /^\{[\s\n]*"/.test(head)) {
      out.push("Likely JSON text (starts with '{')");
    }
  }

  return out;
}

function buildInferenceNotes(
  buf: Buffer,
  entropy: number,
  printable: number,
  magicLabels: string[],
): string[] {
  const notes: string[] = [];
  if (magicLabels.length > 0) {
    notes.push("Magic bytes match known file/container signatures — treat as structured binary or document, not raw ciphertext.");
  } else if (buf.length >= 16 && entropy > 7.2 && printable < 0.45) {
    notes.push(
      "Very high entropy and low printable ratio — consistent with block cipher ciphertext, a compressed blob, or random key material.",
    );
  } else if (buf.length >= 16 && entropy > 6.65 && printable < 0.55) {
    notes.push(
      "Elevated entropy — may be compressed data, encoded binary, or encrypted payload; try nested transforms in the solver pipeline.",
    );
  } else if (printable > 0.85 && entropy < 5.5) {
    notes.push("Mostly printable ASCII with moderate entropy — likely text, armored encoding, or a weak substitution layer.");
  }
  if (buf.length > 0 && buf.length < 8) {
    notes.push("Very short payload — format detection is less reliable.");
  }
  if (buf.length >= 16 && buf.length % 16 === 0 && entropy > 6.5) {
    notes.push(
      `Length is a multiple of 16 bytes (${buf.length} total) — common for AES block alignment (hypothesis only).`,
    );
  }
  return notes;
}

/** Detect JWT-shaped strings (three dot-separated base64url segments). */
function looksLikeJwtArmored(s: string): boolean {
  const t = s.trim();
  if (t.length < 20) return false;
  const parts = t.split(".");
  if (parts.length !== 3) return false;
  const b64u = /^[A-Za-z0-9_-]+$/;
  for (const p of parts) {
    if (p.length < 1 || !b64u.test(p)) return false;
  }
  return true;
}

function looksLikePem(s: string): boolean {
  return /-----BEGIN [A-Z0-9 ]+-----/.test(s);
}

function looksLikeBase64UrlOnly(s: string): boolean {
  const t = s.replace(/\s/g, "");
  if (t.length < 12) return false;
  if (!/^[A-Za-z0-9_-]+=*$/.test(t)) return false;
  if (/^[A-Za-z0-9+/]+=*$/.test(t) && !t.includes("-") && !t.includes("_")) return false;
  return true;
}

/** RFC 4648 Base32 alphabet (padding with =). */
function looksLikeBase32Ascii(s: string): boolean {
  const t = s.replace(/\s/g, "");
  if (t.length < 16) return false;
  if (!/^[A-Z2-7]+=*$/i.test(t)) return false;
  return t.length % 8 === 0;
}

/** Bitcoin / Flickr Base58 — no 0,O,I,l; no standard padding. */
function looksLikeBase58Text(s: string): boolean {
  const t = s.replace(/\s/g, "");
  if (t.length < 24 || t.length > 512) return false;
  if (!/^[1-9A-HJ-NP-Za-km-z]+$/.test(t)) return false;
  if (/[+/=]/.test(t)) return false;
  return true;
}

/**
 * After standard base64 decode of the outer ciphertext, classify what the bytes
 * look like (nested encodings, PEM, JWT, magic files) and fingerprint raw bytes.
 */
export function analyzeDecodedPayload(buf: Buffer): PayloadAnalysisReport {
  const matches: NestedFormatMatch[] = [];
  const { ascii, utf8 } = bufferToScanString(buf);
  const primaryText = utf8 ?? ascii;
  const trimmed = primaryText.trim();

  if (looksLikeBase64Text(buf)) {
    const s = buf.toString("ascii").replace(/\s/g, "");
    const inner = safeBase64Decode(s);
    if (inner && inner.length > 0 && !inner.equals(buf)) {
      matches.push({
        kind: "Nested Base64",
        description: `Inner RFC 4648 decode succeeds (${inner.length} bytes) — likely another layer; unwrap with Base64 again.`,
        detectedSample: truncateSample(s),
      });
    } else {
      matches.push({
        kind: "Nested Base64 (shape)",
        description:
          "Decoded bytes resemble Base64 alphabet — may be ciphertext disguised as Base64 or padding-aligned noise.",
        detectedSample: truncateSample(s),
      });
    }
  }

  if (looksLikeHexAscii(buf)) {
    const hs = buf.toString("ascii").trim();
    matches.push({
      kind: "Hex-encoded (ASCII)",
      description: "Payload is an even-length hexadecimal string — binary may be ciphertext, keys, or structured data.",
      detectedSample: truncateSample(hs),
    });
  }

  if (trimmed.length >= 24 && looksLikeJwtArmored(trimmed)) {
    matches.push({
      kind: "JWT-shaped",
      description: "Three base64url segments separated by dots — could be a signed token or unrelated armoring.",
      detectedSample: truncateSample(trimmed),
    });
  }

  if (trimmed.length >= 32 && looksLikePem(trimmed)) {
    matches.push({
      kind: "PEM / ASCII armor",
      description: "Contains PEM-style BEGIN header — often RSA/EC keys, certificates, or CMS blocks.",
      detectedSample: truncateSample(trimmed),
    });
  }

  if (trimmed.length >= 16 && looksLikeBase64UrlOnly(trimmed) && !looksLikeBase64Text(buf)) {
    matches.push({
      kind: "Base64url-style",
      description:
        "Mostly alphanumeric with - or _ (URL-safe alphabet) — may be base64url without standard +/ padding.",
      detectedSample: truncateSample(trimmed),
    });
  }

  if (trimmed.length >= 16 && looksLikeBase32Ascii(trimmed) && !looksLikeHexAscii(buf)) {
    matches.push({
      kind: "Base32-shaped (ASCII)",
      description:
        "String matches Base32 alphabet (A–Z, 2–7) with padding — try Base32 decode before cryptanalysis.",
      detectedSample: truncateSample(trimmed),
    });
  }

  if (trimmed.length >= 32 && looksLikeBase58Text(trimmed)) {
    matches.push({
      kind: "Base58-shaped",
      description:
        "Character set matches common Base58 (Bitcoin alphabet) — may be an address or encoded key material.",
      detectedSample: truncateSample(trimmed),
    });
  }

  const entropy = shannonEntropy(buf);
  const printable = printableRatio(buf);
  const magicLabels = magicFromBuffer(buf);
  const inferenceNotes = buildInferenceNotes(buf, entropy, printable, magicLabels);

  const fingerprint: ByteFingerprint = {
    byteLength: buf.length,
    hexHead: hexDumpPrefix(buf, 24),
    hexTail: buf.length > 32 ? hexDumpPrefix(buf.subarray(buf.length - 8), 8) : undefined,
    shannonEntropyBits: entropy,
    printableAsciiRatio: printable,
    magicLabels,
    inferenceNotes,
  };

  const hexPatterns = analyzeHexPatterns(buf);

  return { matches, fingerprint, hexPatterns };
}

/** Plain-text block for giant-word-hits.log (or other append-only logs). */
export function formatPayloadAnalysisForLog(report: PayloadAnalysisReport): string {
  const lines: string[] = [];
  lines.push("");
  lines.push(`# ${"=".repeat(72)}`);
  lines.push("# Decoded payload — nested format hints & byte fingerprint");
  lines.push(`# ${"=".repeat(72)}`);
  const fp = report.fingerprint;
  lines.push(`Bytes: ${fp.byteLength}`);
  lines.push(`Hex (first 24 bytes): ${fp.hexHead}`);
  if (fp.hexTail) lines.push(`Hex (last 8 bytes):  ${fp.hexTail}`);
  lines.push(
    `Entropy: ${fp.shannonEntropyBits.toFixed(2)} bits/byte  |  Printable ASCII: ${(fp.printableAsciiRatio * 100).toFixed(1)}%`,
  );
  if (fp.magicLabels.length) {
    lines.push("Magic / file hints:");
    for (const m of fp.magicLabels) lines.push(`  - ${m}`);
  } else {
    lines.push("Magic / file hints: (none matched)");
  }
  if (fp.inferenceNotes.length) {
    lines.push("Inference:");
    for (const n of fp.inferenceNotes) lines.push(`  - ${n}`);
  }
  if (report.matches.length) {
    lines.push("Nested encoding / format matches:");
    for (const x of report.matches) {
      lines.push(`  [${x.kind}] ${x.description}`);
      lines.push(`    sample: ${x.detectedSample}`);
    }
  } else {
    lines.push("Nested encoding / format matches: (none detected)");
  }
  lines.push(...formatHexPatternsForLog(report.hexPatterns));
  lines.push("");
  return lines.join("\n");
}

function formatHexPatternsForLog(hp: HexPatternReport): string[] {
  const lines: string[] = [];
  lines.push("");
  lines.push("# Hex pattern recognition (structure / reverse-engineering hints)");
  lines.push(`# Unique byte values: ${hp.uniqueByteValues}`);
  if (hp.topBytes.length) {
    lines.push(
      "# Most common bytes: " +
        hp.topBytes.map((t) => `0x${t.hex}×${t.count}`).join(", "),
    );
  }
  if (hp.xorHints.length) {
    lines.push(
      "# Top single-byte XOR keys (printable ratio): " +
        hp.xorHints
          .map((x) => `0x${x.keyByte.toString(16).padStart(2, "0")}=${(x.printableRatio * 100).toFixed(1)}%`)
          .join(" · "),
    );
  }
  if (hp.finds.length) {
    lines.push("# Pattern finds:");
    for (const f of hp.finds) {
      lines.push(`  - ${f.title}: ${f.detail}`);
      if (f.suggest) lines.push(`    → ${f.suggest}`);
    }
  } else {
    lines.push("# Pattern finds: (none strong)");
  }
  return lines;
}
