import pc from "picocolors";
import type { ReadabilityReport } from "./englishReadability.js";
import type { CandidatePoolStats } from "./stats.js";
import type { WordHit } from "./wordScan.js";
import type { Candidate } from "./solver.js";
import type { PayloadAnalysisReport } from "./payloadAnalysis.js";
import {
  HEX_PATTERN_PREVIEW_BYTES,
  type HexPatternReport,
} from "./hexPatterns.js";

const W = 84;

function stripAnsi(s: string): string {
  return s.replace(/\u001b\[[\d;]*m/g, "");
}

function dimLine(ch = "─"): string {
  return pc.dim(ch.repeat(W));
}

function boxTop(accent: (s: string) => string = pc.cyan): void {
  console.log(accent("╔" + "═".repeat(W - 2) + "╗"));
}

function boxMid(accent: (s: string) => string = pc.cyan): void {
  console.log(accent("╠" + "═".repeat(W - 2) + "╣"));
}

function boxBottom(accent: (s: string) => string = pc.cyan): void {
  console.log(accent("╚" + "═".repeat(W - 2) + "╝"));
}

/** Single line inside box; pads using visible (ANSI-stripped) width. */
function boxRow(
  text: string,
  accent: (s: string) => string = pc.cyan,
  innerWidth = W - 4,
): void {
  const vis = stripAnsi(text);
  let t = text;
  if (vis.length > innerWidth) {
    t = stripAnsi(text).slice(0, innerWidth - 1) + "…";
  }
  const pad = Math.max(0, innerWidth - stripAnsi(t).length);
  console.log(accent("║") + " " + t + " ".repeat(pad) + " " + accent("║"));
}

/** Left/right columns aligned using visible width (ANSI-safe). */
function lr(left: string, right: string, inner = W - 4): string {
  const gap = Math.max(
    1,
    inner - stripAnsi(left).length - stripAnsi(right).length,
  );
  return left + " ".repeat(gap) + right;
}

function barMeter(
  label: string,
  percent: number,
  width = 30,
  pctColor: (s: string) => string = pc.white,
): string {
  const p = Math.max(0, Math.min(100, percent));
  const filled = Math.round((p / 100) * width);
  const bar =
    pc.green("█".repeat(filled)) +
    pc.dim("░".repeat(Math.max(0, width - filled)));
  return `${pc.dim(label)} ${bar} ${pc.bold(pctColor(String(p)))}${pc.dim("%")}`;
}

/** Opening hero + subtitle. */
export function renderHero(solved: boolean): void {
  console.log("");
  boxTop(pc.magenta);
  boxRow(pc.bold(pc.white("  ⚡ GIANT CIPHER SOLVER")), pc.magenta);
  boxRow(pc.dim("  Black Ops III · The Giant · automated cryptanalysis"), pc.magenta);
  boxMid(pc.magenta);
  const status = solved
    ? pc.green("  STATUS  SOLVED (strict English)")
    : pc.yellow("  STATUS  SEARCH COMPLETE — no strict English match");
  boxRow(status, pc.magenta);
  boxBottom(pc.magenta);
  console.log("");
}

export function renderInputStrip(opts: {
  inputPath: string;
  base64Length: number;
}): void {
  let pathCol = pc.white(opts.inputPath);
  if (stripAnsi(opts.inputPath).length > 56) {
    const v = stripAnsi(opts.inputPath);
    pathCol = pc.dim("…") + pc.white(v.slice(-54));
  }
  boxTop(pc.cyan);
  boxRow(pc.bold(pc.cyan("  INPUT")), pc.cyan);
  boxRow(lr(pc.dim("  File"), pathCol), pc.cyan);
  boxRow(
    lr(
      pc.dim("  Base64 length"),
      pc.bold(String(opts.base64Length)) + pc.dim(" chars"),
    ),
    pc.cyan,
  );
  boxBottom(pc.cyan);
  console.log("");
}

/**
 * After the outer Base64 decodes: nested-format hints (another Base64 layer, hex, JWT, …)
 * plus hex preview and entropy / file-signature guesses. Matches the boxed CLI style.
 */
export function renderPayloadAnalysis(report: PayloadAnalysisReport): void {
  const fp = report.fingerprint;
  boxTop(pc.blue);
  boxRow(pc.bold(pc.blue("  OUTER BASE64 — NESTED FORMAT & BYTE FINGERPRINT")), pc.blue);
  boxMid(pc.blue);

  boxRow(
    lr(
      pc.dim("  Decoded size"),
      pc.white(`${fp.byteLength} bytes`),
    ),
    pc.blue,
  );
  boxRow(
    lr(
      pc.dim("  Shannon entropy"),
      pc.white(`${fp.shannonEntropyBits.toFixed(2)}`) +
        pc.dim(" bits/byte  (max 8)"),
    ),
    pc.blue,
  );
  boxRow(
    lr(
      pc.dim("  Printable ASCII"),
      pc.white(`${(fp.printableAsciiRatio * 100).toFixed(1)}%`),
    ),
    pc.blue,
  );

  const head =
    fp.hexHead.length > W - 18
      ? stripAnsi(fp.hexHead).slice(0, W - 22) + "…"
      : fp.hexHead;
  boxRow(pc.dim("  Hex (first bytes)  ") + pc.white(head), pc.blue);
  if (fp.hexTail) {
    const tail =
      fp.hexTail.length > W - 18
        ? stripAnsi(fp.hexTail).slice(0, W - 22) + "…"
        : fp.hexTail;
    boxRow(pc.dim("  Hex (last bytes)   ") + pc.white(tail), pc.blue);
  }

  boxRow(" ", pc.blue);
  boxRow(pc.bold(pc.white("  File / container signatures")), pc.blue);
  if (fp.magicLabels.length === 0) {
    boxRow(pc.dim("  (no known magic bytes at offset 0)"), pc.blue);
  } else {
    for (const m of fp.magicLabels) {
      const line = m.length > W - 8 ? m.slice(0, W - 12) + "…" : m;
      boxRow(`  ${pc.cyan("•")} ${pc.white(line)}`, pc.blue);
    }
  }

  if (fp.inferenceNotes.length > 0) {
    boxRow(" ", pc.blue);
    boxRow(pc.bold(pc.white("  Likely interpretation")), pc.blue);
    for (const n of fp.inferenceNotes) {
      for (const line of wrapLines(n, W - 6)) {
        boxRow(`  ${pc.dim(line)}`, pc.blue);
      }
    }
  }

  boxRow(" ", pc.blue);
  boxRow(pc.bold(pc.white("  Encoding / encryption-shaped matches")), pc.blue);
  if (report.matches.length === 0) {
    boxRow(
      pc.dim(
        "  No extra armoring detected (no nested Base64 decode, hex, JWT, PEM, …).",
      ),
      pc.blue,
    );
  } else {
    for (const m of report.matches) {
      boxRow(`  ${pc.yellow("▸")} ${pc.bold(pc.cyan(m.kind))}`, pc.blue);
      const desc =
        m.description.length > W - 8
          ? m.description.slice(0, W - 12) + "…"
          : m.description;
      boxRow(`     ${pc.dim(desc)}`, pc.blue);
      const samp =
        m.detectedSample.length > W - 10
          ? m.detectedSample.slice(0, W - 14) + "…"
          : m.detectedSample;
      boxRow(`     ${pc.dim("string:")} ${pc.white(samp)}`, pc.blue);
    }
  }

  boxBottom(pc.blue);
  console.log("");
}

/**
 * Hex dump + pattern recognition (blocks, period, XOR hints) to reason about raw bytes.
 */
export function renderHexPatternPanel(hp: HexPatternReport): void {
  boxTop(pc.green);
  boxRow(pc.bold(pc.green("  HEX PATTERN SCAN — STRUCTURE & SOLVE HINTS")), pc.green);
  boxMid(pc.green);

  boxRow(
    lr(
      pc.dim("  Distinct byte values"),
      pc.white(String(hp.uniqueByteValues)) + pc.dim(" / 256"),
    ),
    pc.green,
  );
  if (hp.topBytes.length > 0) {
    const parts = hp.topBytes
      .map(
        (t) =>
          pc.white(`0x${t.hex}`) +
          pc.dim(` ${t.count}×`) +
          pc.dim(` (${t.pct.toFixed(1)}%)`),
      )
      .join(pc.dim(" · "));
    const line = pc.dim("  Most common bytes  ") + parts;
    if (stripAnsi(line).length <= W - 4) {
      boxRow(line, pc.green);
    } else {
      boxRow(pc.dim("  Most common bytes"), pc.green);
      const joined = hp.topBytes
        .map((t) => `0x${t.hex}×${t.count}`)
        .join(", ");
      for (const wl of wrapLines(joined, W - 6)) {
        boxRow(`  ${pc.dim(wl)}`, pc.green);
      }
    }
  }

  if (hp.xorHints.length > 0) {
    boxRow(" ", pc.green);
    boxRow(pc.bold(pc.white("  Single-byte XOR (printable ASCII %)")), pc.green);
    for (const x of hp.xorHints) {
      boxRow(
        lr(
          pc.dim("    Key"),
          pc.yellow(`0x${x.keyByte.toString(16).padStart(2, "0")}`) +
            pc.dim("  →  ") +
            pc.white(`${(x.printableRatio * 100).toFixed(1)}%`) +
            pc.dim(" printable"),
        ),
        pc.green,
      );
    }
    boxRow(
      pc.dim(
        "    (Solver already runs XOR-1byte on decoded bytes — use this to prioritize hypotheses.)",
      ),
      pc.green,
    );
  }

  if (hp.annotatedLines.length > 0) {
    boxRow(" ", pc.green);
    boxRow(pc.bold(pc.white("  Annotated hex (offset · bytes · ASCII)")), pc.green);
    boxRow(
      pc.dim(`  Showing first ${HEX_PATTERN_PREVIEW_BYTES} bytes · · = non-printable`),
      pc.green,
    );
    for (const L of hp.annotatedLines) {
      const hexPart =
        L.hex.length > W - 28 ? L.hex.slice(0, W - 32) + "…" : L.hex;
      const one =
        pc.dim(L.offset) +
        "  " +
        pc.white(hexPart) +
        "  " +
        pc.cyan(L.ascii);
      if (stripAnsi(one).length > W - 4) {
        boxRow(pc.dim(`  ${L.offset}  `) + pc.white(hexPart), pc.green);
        boxRow(`       ${pc.cyan(L.ascii)}`, pc.green);
      } else {
        boxRow(`  ${one}`, pc.green);
      }
    }
  }

  boxRow(" ", pc.green);
  boxRow(pc.bold(pc.white("  Pattern recognition")), pc.green);
  if (hp.finds.length === 0) {
    boxRow(
      pc.dim(
        "  No strong structural hits (repeated blocks, period, long runs, …).",
      ),
      pc.green,
    );
  } else {
    for (const f of hp.finds) {
      boxRow(`  ${pc.yellow("▸")} ${pc.bold(pc.cyan(f.title))}`, pc.green);
      for (const wl of wrapLines(f.detail, W - 8)) {
        boxRow(`     ${pc.dim(wl)}`, pc.green);
      }
      if (f.suggest) {
        for (const wl of wrapLines(f.suggest, W - 8)) {
          boxRow(`     ${pc.cyan("→")} ${pc.white(wl)}`, pc.green);
        }
      }
    }
  }

  boxBottom(pc.green);
  console.log("");
}

/** Legacy --dump-all mode header. */
export function renderDumpIntro(opts: {
  inputPath: string;
  base64Length: number;
  totalCandidates: number;
  afterFilter: number;
}): void {
  renderHero(false);
  renderInputStrip({ inputPath: opts.inputPath, base64Length: opts.base64Length });
  boxTop(pc.blue);
  boxRow(pc.bold(pc.blue("  HEURISTIC DUMP")), pc.blue);
  boxRow(
    `  ${pc.dim("Pool")}  ${pc.cyan(String(opts.totalCandidates))} ${pc.dim("candidates")}  ${pc.dim("·")}  ${pc.dim("showing")}  ${pc.yellow(String(opts.afterFilter))} ${pc.dim("after filter")}`,
    pc.blue,
  );
  boxBottom(pc.blue);
  console.log("");
}

export interface DashboardOpts {
  elapsedMs: number;
  plausibilityPercent: number;
  solved: boolean;
  pool: CandidatePoolStats;
  xorTried: number;
  vigTried: number;
  xorTimeout: boolean;
  vigTimeout: boolean;
  topTierDelta: number;
  plausibleFloor: number;
}

export function renderStatsDashboard(o: DashboardOpts): void {
  const sec = o.elapsedMs / 1000;
  const kps = sec > 0 ? Math.round((o.xorTried + o.vigTried) / sec) : 0;

  boxTop(pc.blue);
  boxRow(pc.bold(pc.blue("  ANALYTICS DASHBOARD")), pc.blue);
  boxMid(pc.blue);

  // Row: timing + throughput
  const timeStr =
    o.elapsedMs >= 1000
      ? `${(o.elapsedMs / 1000).toFixed(2)} s`
      : `${Math.round(o.elapsedMs)} ms`;
  boxRow(
    lr(
      pc.dim("  Wall time"),
      pc.magenta(timeStr) + pc.dim(`  ·  ~${kps.toLocaleString()} keys/s`),
    ),
    pc.blue,
  );

  boxRow(" ", pc.blue);

  const plColor =
    o.plausibilityPercent >= 80
      ? pc.green
      : o.plausibilityPercent >= 45
        ? pc.yellow
        : pc.red;
  boxRow(
    "  " +
      barMeter("Est. plaintext plausibility", o.plausibilityPercent, 28, plColor) +
      pc.dim("  (heuristic)"),
    pc.blue,
  );
  boxRow(
    pc.dim(
      "      Heuristic 0–100 from ASCII, letters, dictionary hits, χ², quadgrams — not a true probability.",
    ),
    pc.blue,
  );

  boxRow(" ", pc.blue);
  boxRow(pc.bold(pc.white("  CANDIDATE LANDSCAPE")), pc.blue);
  boxRow(
    lr(pc.dim("  Total transform outputs"), pc.cyan(String(o.pool.total))),
    pc.blue,
  );
  boxRow(
    lr(
      pc.dim("  Best heuristic score"),
      pc.green(o.pool.bestScore.toFixed(2)),
    ),
    pc.blue,
  );
  boxRow(
    lr(
      pc.dim("  Worst score (tail)"),
      pc.dim(o.pool.worstScore.toFixed(2)),
    ),
    pc.blue,
  );
  boxRow(
    lr(
      pc.dim("  Score spread (max − min)"),
      pc.yellow(o.pool.scoreSpread.toFixed(2)),
    ),
    pc.blue,
  );
  boxRow(
    lr(
      pc.dim("  Mean of top 5 scores"),
      pc.white(o.pool.avgTop5Score.toFixed(2)),
    ),
    pc.blue,
  );
  boxRow(
    lr(
      pc.dim("  Median score (sorted pool)"),
      pc.white(o.pool.medianScore.toFixed(2)),
    ),
    pc.blue,
  );
  boxRow(
    lr(
      pc.dim(`  Top tier (±${o.topTierDelta} of best)`),
      pc.cyan(String(o.pool.topTierCount)),
    ),
    pc.blue,
  );
  boxRow(
    lr(
      pc.dim(`  Plausible floor (≥ ${o.plausibleFloor})`),
      pc.cyan(String(o.pool.plausibleCount)),
    ),
    pc.blue,
  );

  boxRow(" ", pc.blue);
  boxRow(pc.bold(pc.white("  BRUTE-FORCE")), pc.blue);
  const xorLine =
    pc.white(o.xorTried.toLocaleString()) +
    (o.xorTimeout ? pc.red("  TIMEOUT") : pc.dim("  complete"));
  const vigLine =
    pc.white(o.vigTried.toLocaleString()) +
    (o.vigTimeout ? pc.red("  TIMEOUT") : pc.dim("  complete"));
  boxRow(lr(pc.dim("  XOR keys tried ([a-zA-Z0-9]^n)"), xorLine), pc.blue);
  boxRow(lr(pc.dim("  Vigenère + Beaufort on Base64"), vigLine), pc.blue);

  if (o.pool.topMethods.length > 0) {
    boxRow(" ", pc.blue);
    boxRow(pc.bold(pc.white("  TRANSFORM MIX (top methods)")), pc.blue);
    for (const row of o.pool.topMethods) {
      const pct = ((row.count / o.pool.total) * 100).toFixed(1);
      boxRow(
        lr(
          pc.dim(`    ${row.method}`),
          pc.white(String(row.count)) + pc.dim(`  (${pct}%)`),
        ),
        pc.blue,
      );
    }
  }

  boxBottom(pc.blue);
  console.log("");
}

export function renderPhasesPipeline(phases: string[]): void {
  boxTop(pc.yellow);
  boxRow(pc.bold(pc.yellow("  EXECUTION PIPELINE")), pc.yellow);
  boxMid(pc.yellow);
  const joined = phases
    .map((p, i) => {
      const n = pc.dim(`${i + 1}.`);
      const name = pc.cyan(p);
      return `${n}${name}`;
    })
    .join(pc.dim("  →  "));
  const line = "  " + joined;
  if (stripAnsi(line).length <= W - 4) {
    boxRow(line, pc.yellow);
  } else {
    for (const p of phases) {
      boxRow(`  ${pc.dim("•")} ${pc.cyan(p)}`, pc.yellow);
    }
  }
  boxBottom(pc.yellow);
  console.log("");
}

export function renderWordHits(hits: WordHit[], maxShow = 14): void {
  boxTop(pc.green);
  boxRow(
    pc.bold(pc.green(`  DICTIONARY TOKEN SCAN  (${hits.length} hit${hits.length === 1 ? "" : "s"})`)),
    pc.green,
  );
  boxMid(pc.green);
  if (hits.length === 0) {
    boxRow(pc.dim("  No English dictionary tokens (length ≥3) in primary plaintext."), pc.green);
    boxBottom(pc.green);
    console.log("");
    return;
  }
  const show = hits.slice(0, maxShow);
  for (const h of show) {
    boxRow(
      `  ${pc.dim(`[${h.start}:${h.end}]`)}  ${pc.bold(pc.green(`“${h.word}”`))}`,
      pc.green,
    );
    const ctx =
      h.contextLine.length > W - 8
        ? h.contextLine.slice(0, W - 12) + " …"
        : h.contextLine;
    boxRow(pc.dim(`      ${ctx}`), pc.green);
    const caret = " ".repeat(Math.min(W - 14, 6 + h.contextWordStart)) + pc.magenta("^");
    boxRow(caret, pc.green);
  }
  if (hits.length > maxShow) {
    boxRow(pc.dim(`  … ${hits.length - maxShow} more in log file`), pc.green);
  }
  boxBottom(pc.green);
  console.log("");
}

export function renderLogFooter(path: string): void {
  console.log(
    pc.dim("  📄 Word positions & session log: ") + pc.white(pc.underline(path)),
  );
  console.log("");
}

export function renderOutcomeBanner(solved: boolean): void {
  if (solved) {
    boxTop(pc.green);
    boxRow(
      pc.bold(pc.green("  ✓  STRICT ENGLISH CHECK PASSED")),
      pc.green,
    );
    boxRow(pc.dim("  Candidate treated as readable plaintext under dictionary + stats rules."), pc.green);
    boxBottom(pc.green);
  } else {
    boxTop(pc.yellow);
    boxRow(pc.bold(pc.yellow("  ◆  NO STRICT ENGLISH MATCH")), pc.yellow);
    boxRow(
      pc.dim("  The real method may differ (layering, non-alphanumeric key, non-XOR/Vigenère path)."),
      pc.yellow,
    );
    boxBottom(pc.yellow);
  }
  console.log("");
}

export function renderCandidateCard(c: Candidate, title: string): void {
  boxTop(pc.magenta);
  boxRow(pc.bold(pc.magenta(`  ${title.toUpperCase()}`)), pc.magenta);
  boxMid(pc.magenta);
  const m = c.meta;
  if (m) {
  boxRow(
    lr(
      pc.dim("  Heuristic score"),
      pc.bold(pc.white(c.score.toFixed(2))),
    ),
    pc.magenta,
  );
  boxRow(
    lr(pc.dim("  χ² (letters)"), pc.white(m.chiSq.toFixed(1))),
    pc.magenta,
  );
  boxRow(
    lr(
      pc.dim("  ASCII / letters"),
      pc.white(
        `${(m.printableRatio * 100).toFixed(0)}% / ${(m.letterRatio * 100).toFixed(0)}%`,
      ),
    ),
    pc.magenta,
  );
  }
  const detail = `${c.method}  │  ${c.detail}`;
  const d =
    detail.length > W - 8 ? detail.slice(0, W - 12) + " …" : detail;
  boxRow(pc.dim(`  ${d}`), pc.magenta);
  boxMid(pc.magenta);
  const body = plainTruncate(c.text, 960);
  for (const line of wrapLines(body, W - 6)) {
    boxRow(pc.white("  " + line), pc.magenta);
  }
  boxBottom(pc.magenta);
  console.log("");
}

export function renderReadabilityCard(r: ReadabilityReport): void {
  boxTop(pc.cyan);
  boxRow(pc.bold(pc.cyan("  READABILITY (STRICT GATE)")), pc.cyan);
  boxMid(pc.cyan);
  boxRow(
    lr(pc.dim("  ASCII ratio"), pc.white(`${(r.asciiRatio * 100).toFixed(1)}%`)),
    pc.cyan,
  );
  boxRow(
    lr(
      pc.dim("  Letter ratio"),
      pc.white(`${(r.letterRatio * 100).toFixed(1)}%`),
    ),
    pc.cyan,
  );
  boxRow(
    lr(
      pc.dim("  Dictionary word hits"),
      pc.white(String(r.dictWordHits)),
    ),
    pc.cyan,
  );
  boxRow(
    lr(
      pc.dim("  Token match ratio"),
      pc.white(`${(r.dictWordRatio * 100).toFixed(1)}%`),
    ),
    pc.cyan,
  );
  boxRow(lr(pc.dim("  χ²"), pc.white(r.chiSq.toFixed(1))), pc.cyan);
  boxRow(
    lr(
      pc.dim("  Quadgram density"),
      pc.white(r.quadgramHits.toFixed(5)),
    ),
    pc.cyan,
  );
  if (!r.passes && r.reasons.length) {
    boxMid(pc.cyan);
    const reasons = r.reasons.join(", ");
    const wrapped = wrapLines(`Failures: ${reasons}`, W - 6);
    for (const line of wrapped) {
      boxRow(pc.red("  " + line), pc.cyan);
    }
  }
  boxBottom(pc.cyan);
  console.log("");
}

function wrapLines(s: string, maxLen: number): string[] {
  const words = s.split(/\s+/);
  const lines: string[] = [];
  let cur = "";
  for (const w of words) {
    const next = cur ? `${cur} ${w}` : w;
    if (next.length <= maxLen) cur = next;
    else {
      if (cur) lines.push(cur);
      cur = w.length > maxLen ? w.slice(0, maxLen - 1) + "…" : w;
    }
  }
  if (cur) lines.push(cur);
  return lines.length ? lines : [""];
}

function plainTruncate(s: string, n: number): string {
  if (s.length <= n) return s;
  return `${s.slice(0, n)} … (${s.length - n} more chars)`;
}

// --- Legacy names (re-export thin wrappers for any internal use) ---

export const banner = (title: string) => {
  boxTop();
  boxRow(pc.bold(title));
  boxBottom();
};

export const section = (title: string) => {
  console.log(pc.bold(pc.yellow(`▸ ${title}`)));
  console.log(dimLine());
};

export const kv = (
  key: string,
  value: string,
  valueColor: (s: string) => string = pc.white,
) => {
  console.log(`  ${pc.dim(key.padEnd(22))} ${valueColor(value)}`);
};

export function statsBlock(opts: DashboardOpts): void {
  renderStatsDashboard(opts);
}

export const phasesRow = renderPhasesPipeline;
export const wordHitsConsole = renderWordHits;
export const candidateBlock = renderCandidateCard;
export const readabilityBlock = renderReadabilityCard;
export const solvedBanner = () => renderOutcomeBanner(true);
export const unsolvedBanner = () => renderOutcomeBanner(false);
export const logFileNote = renderLogFooter;
