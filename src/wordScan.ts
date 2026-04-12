import { appendFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { getDictionaryWordSet } from "./englishReadability.js";

export interface WordHit {
  /** Matched word (lowercase). */
  word: string;
  /** Inclusive start index in the analyzed string. */
  start: number;
  /** Exclusive end index. */
  end: number;
  /** Snippet around the match (newlines shown as ↵). */
  contextLine: string;
  /** Character offset in contextLine where the word begins (for marking). */
  contextWordStart: number;
}

const CTX = 28;

/**
 * Find dictionary English words in plaintext as letter-only tokens (A–Z / a–z),
 * with character indices into `text`.
 */
export function scanForDictionaryWords(
  text: string,
  minWordLen = 3,
  dict: Set<string> = getDictionaryWordSet(),
): WordHit[] {
  const hits: WordHit[] = [];
  const re = /[A-Za-z]+/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const raw = m[0];
    const lw = raw.toLowerCase();
    if (lw.length < minWordLen) continue;
    if (!dict.has(lw)) continue;
    const start = m.index;
    const end = start + raw.length;
    const ctxStart = Math.max(0, start - CTX);
    const ctxEnd = Math.min(text.length, end + CTX);
    const contextLine = text
      .slice(ctxStart, ctxEnd)
      .replace(/\r\n/g, "↵")
      .replace(/\n/g, "↵")
      .replace(/\r/g, "↵");
    const contextWordStart = start - ctxStart;
    hits.push({
      word: lw,
      start,
      end,
      contextLine,
      contextWordStart,
    });
  }
  return hits;
}

export interface WordLogSectionMeta {
  sourceLabel: string;
  plaintextLength: number;
  method?: string;
  detail?: string;
}

export interface SessionWordLogMeta {
  timestamp: string;
  durationMs: number;
  cipherBase64Length: number;
}

function formatHitsBlock(
  meta: WordLogSectionMeta,
  hits: WordHit[],
): string {
  const lines: string[] = [];
  lines.push("");
  lines.push(`${"#".repeat(3)} ${meta.sourceLabel}`);
  if (meta.method) lines.push(`Method: ${meta.method}`);
  if (meta.detail) lines.push(`Detail: ${meta.detail}`);
  lines.push(`Length: ${meta.plaintextLength} | Dictionary hits: ${hits.length}`);
  lines.push("-".repeat(72));

  if (hits.length === 0) {
    lines.push("(no dictionary words in this string)");
    lines.push("");
    return lines.join("\n");
  }

  for (const h of hits) {
    const pad = " ".repeat(Math.max(0, h.contextWordStart));
    lines.push(`[${h.start}:${h.end}] "${h.word}"`);
    lines.push(`  context: ${h.contextLine}`);
    lines.push(`  marker:  ${pad}^`);
    lines.push("");
  }
  return lines.join("\n");
}

/** Default log path in cwd; override with GIANT_WORD_LOG. */
export function defaultWordLogPath(cwd = process.cwd()): string {
  const fromEnv = process.env.GIANT_WORD_LOG;
  if (fromEnv && fromEnv.length > 0) return fromEnv;
  return join(cwd, "giant-word-hits.log");
}

/**
 * One run = one file: ciphertext string + each analyzed plaintext section with positions.
 */
export function writeSessionWordLog(
  path: string,
  session: SessionWordLogMeta,
  sections: Array<WordLogSectionMeta & { text: string }>,
): void {
  const head: string[] = [];
  head.push(`# ${"=".repeat(72)}`);
  head.push(`# Giant Cipher — dictionary word positions (token scan, min length ≥3)`);
  head.push(`# ${session.timestamp}`);
  head.push(`# Run duration: ${session.durationMs >= 1000 ? `${(session.durationMs / 1000).toFixed(2)}s` : `${Math.round(session.durationMs)}ms`}`);
  head.push(`# Base64 ciphertext length: ${session.cipherBase64Length}`);
  head.push(`# ${"=".repeat(72)}`);

  const parts: string[] = [head.join("\n")];
  for (const s of sections) {
    const hits = scanForDictionaryWords(s.text);
    const { text: _t, ...meta } = s;
    parts.push(formatHitsBlock(meta, hits));
  }

  writeFileSync(path, parts.join("\n") + "\n", "utf8");
}

/** Append a single section (optional tooling). */
export function appendWordHitsSection(
  path: string,
  meta: WordLogSectionMeta,
  hits: WordHit[],
): void {
  appendFileSync(path, formatHitsBlock(meta, hits), "utf8");
}
