import pc from "picocolors";
import { COD_CIPHER_SUITE_SECTIONS } from "./codCipherSuite.js";
import { getUiWidth } from "./uiWidth.js";
function boxOuterW() {
    return getUiWidth();
}
function innerW() {
    return Math.max(12, boxOuterW() - 4);
}
function stripAnsi(s) {
    return s.replace(/\u001b\[[\d;]*m/g, "");
}
function dimLine(ch = "─") {
    return pc.dim(ch.repeat(boxOuterW()));
}
function boxTop(accent = pc.cyan) {
    const W = boxOuterW();
    console.log(accent("╔" + "═".repeat(W - 2) + "╗"));
}
function boxMid(accent = pc.cyan) {
    const W = boxOuterW();
    console.log(accent("╠" + "═".repeat(W - 2) + "╣"));
}
function boxBottom(accent = pc.cyan) {
    const W = boxOuterW();
    console.log(accent("╚" + "═".repeat(W - 2) + "╝"));
}
/**
 * Boxed row: pads short lines; long lines hard-wrap to multiple rows (plain text
 * after wrap — avoids ellipsis; ANSI may flatten on wrapped segments).
 */
function boxRow(text, accent = pc.cyan, innerWidth = innerW()) {
    const plain = stripAnsi(text);
    if (plain.length <= innerWidth) {
        const pad = Math.max(0, innerWidth - plain.length);
        console.log(accent("║") + " " + text + " ".repeat(pad) + " " + accent("║"));
        return;
    }
    for (let i = 0; i < plain.length; i += innerWidth) {
        const chunk = plain.slice(i, i + innerWidth);
        const pad = Math.max(0, innerWidth - chunk.length);
        console.log(accent("║") + " " + chunk + " ".repeat(pad) + " " + accent("║"));
    }
}
/** Left/right columns aligned using visible width (ANSI-safe). */
function lr(left, right, inner = innerW()) {
    const gap = Math.max(1, inner - stripAnsi(left).length - stripAnsi(right).length);
    return left + " ".repeat(gap) + right;
}
function barMeter(label, percent, width = 30, pctColor = pc.white) {
    const p = Math.max(0, Math.min(100, percent));
    const filled = Math.round((p / 100) * width);
    const bar = pc.green("█".repeat(filled)) +
        pc.dim("░".repeat(Math.max(0, width - filled)));
    return `${pc.dim(label)} ${bar} ${pc.bold(pctColor(String(p)))}${pc.dim("%")}`;
}
/** Opening hero + subtitle. */
export function renderHero(solved) {
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
/**
 * Static catalog of implemented transforms (COD Zombies–aligned + general cryptanalysis).
 */
export function renderCodCipherSuiteCatalog() {
    boxTop(pc.yellow);
    boxRow(pc.bold(pc.yellow("  CALL OF DUTY ZOMBIES — CIPHER SUITE (IMPLEMENTED)")), pc.yellow);
    boxMid(pc.yellow);
    boxRow(pc.dim("  Methods below are what this CLI actually runs (plus brute XOR/Vigenère phases)."), pc.yellow);
    boxRow(" ", pc.yellow);
    for (const sec of COD_CIPHER_SUITE_SECTIONS) {
        boxRow(pc.bold(pc.white(`  ${sec.title}`)), pc.yellow);
        for (const line of sec.lines) {
            for (const wl of wrapLines(`  • ${line}`, innerW() - 2)) {
                boxRow(pc.dim(wl), pc.yellow);
            }
        }
        boxRow(" ", pc.yellow);
    }
    boxBottom(pc.yellow);
    console.log("");
}
export function renderInputStrip(opts) {
    const pathCol = pc.white(opts.inputPath);
    boxTop(pc.cyan);
    boxRow(pc.bold(pc.cyan("  INPUT")), pc.cyan);
    boxRow(lr(pc.dim("  File"), pathCol), pc.cyan);
    boxRow(lr(pc.dim("  Base64 length"), pc.bold(String(opts.base64Length)) + pc.dim(" chars")), pc.cyan);
    boxBottom(pc.cyan);
    console.log("");
}
/**
 * After the outer Base64 decodes: nested-format hints (another Base64 layer, hex, JWT, …)
 * plus hex preview and entropy / file-signature guesses. Matches the boxed CLI style.
 */
export function renderPayloadAnalysis(report) {
    const fp = report.fingerprint;
    boxTop(pc.blue);
    boxRow(pc.bold(pc.blue("  OUTER BASE64 — NESTED FORMAT & BYTE FINGERPRINT")), pc.blue);
    boxMid(pc.blue);
    boxRow(lr(pc.dim("  Decoded size"), pc.white(`${fp.byteLength} bytes`)), pc.blue);
    boxRow(lr(pc.dim("  Shannon entropy"), pc.white(`${fp.shannonEntropyBits.toFixed(2)}`) +
        pc.dim(" bits/byte  (max 8)")), pc.blue);
    boxRow(lr(pc.dim("  Printable ASCII"), pc.white(`${(fp.printableAsciiRatio * 100).toFixed(1)}%`)), pc.blue);
    boxRow(pc.dim("  Hex (first bytes)  ") + pc.white(fp.hexHead), pc.blue);
    if (fp.hexTail) {
        boxRow(pc.dim("  Hex (last bytes)   ") + pc.white(fp.hexTail), pc.blue);
    }
    boxRow(" ", pc.blue);
    boxRow(pc.bold(pc.white("  File / container signatures")), pc.blue);
    if (fp.magicLabels.length === 0) {
        boxRow(pc.dim("  (no known magic bytes at offset 0)"), pc.blue);
    }
    else {
        for (const m of fp.magicLabels) {
            boxRow(`  ${pc.cyan("•")} ${pc.white(m)}`, pc.blue);
        }
    }
    if (fp.inferenceNotes.length > 0) {
        boxRow(" ", pc.blue);
        boxRow(pc.bold(pc.white("  Likely interpretation")), pc.blue);
        for (const n of fp.inferenceNotes) {
            for (const line of wrapLines(n, innerW() - 2)) {
                boxRow(`  ${pc.dim(line)}`, pc.blue);
            }
        }
    }
    boxRow(" ", pc.blue);
    boxRow(pc.bold(pc.white("  Encoding / encryption-shaped matches")), pc.blue);
    if (report.matches.length === 0) {
        boxRow(pc.dim("  No extra armoring detected (no nested Base64 decode, hex, JWT, PEM, …)."), pc.blue);
    }
    else {
        for (const m of report.matches) {
            boxRow(`  ${pc.yellow("▸")} ${pc.bold(pc.cyan(m.kind))}`, pc.blue);
            boxRow(`     ${pc.dim(m.description)}`, pc.blue);
            boxRow(`     ${pc.dim("string:")} ${pc.white(m.detectedSample)}`, pc.blue);
        }
    }
    boxBottom(pc.blue);
    console.log("");
}
/**
 * Hex dump + pattern recognition (blocks, period, XOR hints) to reason about raw bytes.
 */
export function renderHexPatternPanel(hp) {
    boxTop(pc.green);
    boxRow(pc.bold(pc.green("  HEX PATTERN SCAN — STRUCTURE & SOLVE HINTS")), pc.green);
    boxMid(pc.green);
    boxRow(lr(pc.dim("  Distinct byte values"), pc.white(String(hp.uniqueByteValues)) + pc.dim(" / 256")), pc.green);
    if (hp.topBytes.length > 0) {
        const parts = hp.topBytes
            .map((t) => pc.white(`0x${t.hex}`) +
            pc.dim(` ${t.count}×`) +
            pc.dim(` (${t.pct.toFixed(1)}%)`))
            .join(pc.dim(" · "));
        boxRow(pc.dim("  Most common bytes  ") + parts, pc.green);
    }
    if (hp.xorHints.length > 0) {
        boxRow(" ", pc.green);
        boxRow(pc.bold(pc.white("  Single-byte XOR (printable ASCII %)")), pc.green);
        for (const x of hp.xorHints) {
            boxRow(lr(pc.dim("    Key"), pc.yellow(`0x${x.keyByte.toString(16).padStart(2, "0")}`) +
                pc.dim("  →  ") +
                pc.white(`${(x.printableRatio * 100).toFixed(1)}%`) +
                pc.dim(" printable")), pc.green);
        }
        boxRow(pc.dim("    (Solver already runs XOR-1byte on decoded bytes — use this to prioritize hypotheses.)"), pc.green);
    }
    if (hp.annotatedLines.length > 0) {
        boxRow(" ", pc.green);
        boxRow(pc.bold(pc.white("  Annotated hex (offset · bytes · ASCII)")), pc.green);
        boxRow(pc.dim(`  Annotated ${hp.bytesAnnotated} byte(s) (cap via GIANT_HEX_DUMP_BYTES) · · = non-printable`), pc.green);
        for (const L of hp.annotatedLines) {
            const one = pc.dim(L.offset) +
                "  " +
                pc.white(L.hex) +
                "  " +
                pc.cyan(L.ascii);
            boxRow(`  ${one}`, pc.green);
        }
    }
    boxRow(" ", pc.green);
    boxRow(pc.bold(pc.white("  Pattern recognition")), pc.green);
    if (hp.finds.length === 0) {
        boxRow(pc.dim("  No strong structural hits (repeated blocks, period, long runs, …)."), pc.green);
    }
    else {
        for (const f of hp.finds) {
            boxRow(`  ${pc.yellow("▸")} ${pc.bold(pc.cyan(f.title))}`, pc.green);
            for (const wl of wrapLines(f.detail, innerW() - 4)) {
                boxRow(`     ${pc.dim(wl)}`, pc.green);
            }
            if (f.suggest) {
                for (const wl of wrapLines(f.suggest, innerW() - 4)) {
                    boxRow(`     ${pc.cyan("→")} ${pc.white(wl)}`, pc.green);
                }
            }
        }
    }
    boxBottom(pc.green);
    console.log("");
}
/**
 * Per-family cipher likelihoods, multi-layer unwrap hypotheses, and falsifiable critique.
 * Fits the same boxed terminal UI as other analyst panels.
 */
export function renderCipherIntelligence(report) {
    const accent = pc.magenta;
    const st = report.stats;
    boxTop(accent);
    boxRow(pc.bold(accent("  CIPHER INTELLIGENCE — PREDICTIONS × LAYERS × CRITIQUE")), accent);
    boxMid(accent);
    boxRow(pc.bold(pc.white("  Quick statistics")), accent);
    boxRow(lr(pc.dim("  Index of coincidence"), st.indexOfCoincidence !== null
        ? pc.white(st.indexOfCoincidence.toFixed(4)) +
            pc.dim(`  (English ~${st.englishExpectedIoc}; n=${st.letterCountForIoc} letters)`)
        : pc.dim("n/a — too few A–Z letters in buffer")), accent);
    boxRow(lr(pc.dim("  Byte entropy"), pc.white(`${st.byteEntropyBits.toFixed(2)}`) + pc.dim(" bits/byte")), accent);
    boxRow(lr(pc.dim("  Printable ASCII"), pc.white(`${(st.printableAsciiRatio * 100).toFixed(1)}%`)), accent);
    const zlibLine = st.zlibInflateLikely
        ? pc.green("inflate OK") +
            pc.dim(`  (size ratio ${st.zlibSizeRatio?.toFixed(3) ?? "?"})`)
        : pc.dim("no zlib/gzip inflate on raw buffer");
    boxRow(lr(pc.dim("  Compression probe"), zlibLine), accent);
    if (st.approxPeriodFromStructure) {
        boxRow(lr(pc.dim("  Structural period hint"), pc.yellow(String(st.approxPeriodFromStructure))), accent);
    }
    boxRow(lr(pc.dim("  Best pool candidate"), pc.white(st.bestCandidateMethod ?? "—") +
        pc.dim("  score ") +
        pc.white(st.bestCandidateScore !== null ? st.bestCandidateScore.toFixed(2) : "—")), accent);
    boxRow(" ", accent);
    boxRow(pc.bold(pc.white("  Cipher-family predictions (heuristic confidence)")), accent);
    const predBarW = Math.max(14, Math.min(36, innerW() - 44));
    for (const p of report.predictions) {
        const filled = Math.round((p.confidence / 100) * predBarW);
        const bar = pc.green("█".repeat(filled)) +
            pc.dim("░".repeat(Math.max(0, predBarW - filled)));
        boxRow(`  ${pc.yellow("▸")} ${pc.bold(pc.cyan(p.label))}`, accent);
        boxRow("     " +
            pc.bold(pc.white(String(p.confidence).padStart(3))) +
            pc.dim("% ") +
            bar, accent);
        for (const wl of wrapLines(p.summary, innerW() - 6)) {
            boxRow(`     ${pc.dim(wl)}`, accent);
        }
        for (const ev of p.evidence.slice(0, 4)) {
            for (const wl of wrapLines(`· ${ev}`, innerW() - 6)) {
                boxRow(`     ${pc.dim(wl)}`, accent);
            }
        }
        if (p.evidence.length > 4) {
            boxRow(`     ${pc.dim(`… ${p.evidence.length - 4} more in log`)}`, accent);
        }
    }
    boxRow(" ", accent);
    boxRow(pc.bold(pc.white("  Multi-layer hypotheses (outer → inner)")), accent);
    for (const L of report.layerHypotheses) {
        boxRow(lr(pc.dim(`  #${L.rank}`), pc.yellow(`${L.confidence}%`) + pc.dim("  confidence")), accent);
        const plainChain = L.chain.join(" → ");
        for (const wl of wrapLines(`  ${plainChain}`, innerW() - 2)) {
            boxRow(pc.cyan(wl), accent);
        }
        for (const wl of wrapLines(L.notes, innerW() - 4)) {
            boxRow(`    ${pc.dim(wl)}`, accent);
        }
        boxRow(" ", accent);
    }
    boxRow(pc.bold(pc.white("  Critical analysis (how to read these results)")), accent);
    for (const i of report.insights) {
        boxRow(`  ${pc.yellow("◆")} ${pc.bold(pc.white(i.title))}`, accent);
        for (const wl of wrapLines(`Obs: ${i.observation}`, innerW() - 4)) {
            boxRow(`    ${pc.dim(wl)}`, accent);
        }
        for (const wl of wrapLines(`→ ${i.interpretation}`, innerW() - 4)) {
            boxRow(`    ${pc.cyan(wl)}`, accent);
        }
        for (const wl of wrapLines(`Falsify: ${i.falsify}`, innerW() - 4)) {
            boxRow(`    ${pc.red(wl)}`, accent);
        }
        boxRow(" ", accent);
    }
    if (st.topSolverMethods.length > 0) {
        boxRow(pc.dim("  Solver method mix (top):"), accent);
        const row = st.topSolverMethods
            .slice(0, 6)
            .map((m) => `${m.method}×${m.count}`)
            .join(pc.dim(" · "));
        for (const wl of wrapLines(`  ${row}`, innerW() - 2)) {
            boxRow(wl, accent);
        }
    }
    boxBottom(accent);
    console.log("");
}
/** Legacy --dump-all mode header. */
export function renderDumpIntro(opts) {
    renderHero(false);
    renderInputStrip({ inputPath: opts.inputPath, base64Length: opts.base64Length });
    boxTop(pc.blue);
    boxRow(pc.bold(pc.blue("  HEURISTIC DUMP")), pc.blue);
    boxRow(`  ${pc.dim("Pool")}  ${pc.cyan(String(opts.totalCandidates))} ${pc.dim("candidates")}  ${pc.dim("·")}  ${pc.dim("showing")}  ${pc.yellow(String(opts.afterFilter))} ${pc.dim("after filter")}`, pc.blue);
    boxBottom(pc.blue);
    console.log("");
}
export function renderStatsDashboard(o) {
    const sec = o.elapsedMs / 1000;
    const kps = sec > 0 ? Math.round((o.xorTried + o.vigTried) / sec) : 0;
    boxTop(pc.blue);
    boxRow(pc.bold(pc.blue("  ANALYTICS DASHBOARD")), pc.blue);
    boxMid(pc.blue);
    // Row: timing + throughput
    const timeStr = o.elapsedMs >= 1000
        ? `${(o.elapsedMs / 1000).toFixed(2)} s`
        : `${Math.round(o.elapsedMs)} ms`;
    boxRow(lr(pc.dim("  Wall time"), pc.magenta(timeStr) + pc.dim(`  ·  ~${kps.toLocaleString()} keys/s`)), pc.blue);
    boxRow(" ", pc.blue);
    const plColor = o.plausibilityPercent >= 80
        ? pc.green
        : o.plausibilityPercent >= 45
            ? pc.yellow
            : pc.red;
    const plBarW = Math.max(18, Math.min(52, innerW() - 48));
    boxRow("  " +
        barMeter("Est. plaintext plausibility", o.plausibilityPercent, plBarW, plColor) +
        pc.dim("  (heuristic)"), pc.blue);
    boxRow(pc.dim("      Heuristic 0–100 from ASCII, letters, dictionary hits, χ², quadgrams — not a true probability."), pc.blue);
    boxRow(" ", pc.blue);
    boxRow(pc.bold(pc.white("  CANDIDATE LANDSCAPE")), pc.blue);
    boxRow(lr(pc.dim("  Total transform outputs"), pc.cyan(String(o.pool.total))), pc.blue);
    boxRow(lr(pc.dim("  Best heuristic score"), pc.green(o.pool.bestScore.toFixed(2))), pc.blue);
    boxRow(lr(pc.dim("  Worst score (tail)"), pc.dim(o.pool.worstScore.toFixed(2))), pc.blue);
    boxRow(lr(pc.dim("  Score spread (max − min)"), pc.yellow(o.pool.scoreSpread.toFixed(2))), pc.blue);
    boxRow(lr(pc.dim("  Mean of top 5 scores"), pc.white(o.pool.avgTop5Score.toFixed(2))), pc.blue);
    boxRow(lr(pc.dim("  Median score (sorted pool)"), pc.white(o.pool.medianScore.toFixed(2))), pc.blue);
    boxRow(lr(pc.dim(`  Top tier (±${o.topTierDelta} of best)`), pc.cyan(String(o.pool.topTierCount))), pc.blue);
    boxRow(lr(pc.dim(`  Plausible floor (≥ ${o.plausibleFloor})`), pc.cyan(String(o.pool.plausibleCount))), pc.blue);
    boxRow(" ", pc.blue);
    boxRow(pc.bold(pc.white("  BRUTE-FORCE")), pc.blue);
    const xorLine = pc.white(o.xorTried.toLocaleString()) +
        (o.xorTimeout ? pc.red("  TIMEOUT") : pc.dim("  complete"));
    const vigLine = pc.white(o.vigTried.toLocaleString()) +
        (o.vigTimeout ? pc.red("  TIMEOUT") : pc.dim("  complete"));
    boxRow(lr(pc.dim("  XOR keys tried ([a-zA-Z0-9]^n)"), xorLine), pc.blue);
    boxRow(lr(pc.dim("  Vigenère + Beaufort on Base64"), vigLine), pc.blue);
    if (o.pool.topMethods.length > 0) {
        boxRow(" ", pc.blue);
        boxRow(pc.bold(pc.white("  TRANSFORM MIX (top methods)")), pc.blue);
        for (const row of o.pool.topMethods) {
            const pct = ((row.count / o.pool.total) * 100).toFixed(1);
            boxRow(lr(pc.dim(`    ${row.method}`), pc.white(String(row.count)) + pc.dim(`  (${pct}%)`)), pc.blue);
        }
    }
    boxBottom(pc.blue);
    console.log("");
}
export function renderPhasesPipeline(phases) {
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
    boxRow("  " + joined, pc.yellow);
    boxBottom(pc.yellow);
    console.log("");
}
function wrapHardPlain(plain, maxLen) {
    if (maxLen < 4)
        return [plain];
    const lines = [];
    for (let i = 0; i < plain.length; i += maxLen) {
        lines.push(plain.slice(i, i + maxLen));
    }
    return lines.length ? lines : [""];
}
/** Max candidate plaintext chars in the UI (default: unlimited). Set `GIANT_CANDIDATE_TEXT_MAX` to cap. */
function maxCandidateBodyChars() {
    const raw = process.env.GIANT_CANDIDATE_TEXT_MAX;
    if (raw === undefined || raw === "")
        return Number.POSITIVE_INFINITY;
    if (raw === "0" || raw.toLowerCase() === "full") {
        return Number.POSITIVE_INFINITY;
    }
    const n = Number.parseInt(raw, 10);
    if (!Number.isFinite(n) || n < 0)
        return Number.POSITIVE_INFINITY;
    return n;
}
function candidateBodyForDisplay(s) {
    const max = maxCandidateBodyChars();
    if (!Number.isFinite(max) || s.length <= max)
        return s;
    return plainTruncate(s, max);
}
export function renderWordHits(hits, maxShow = Number.POSITIVE_INFINITY) {
    boxTop(pc.green);
    boxRow(pc.bold(pc.green(`  DICTIONARY TOKEN SCAN  (${hits.length} hit${hits.length === 1 ? "" : "s"})`)), pc.green);
    boxMid(pc.green);
    if (hits.length === 0) {
        boxRow(pc.dim("  No English dictionary tokens (length ≥3) in primary plaintext."), pc.green);
        boxBottom(pc.green);
        console.log("");
        return;
    }
    const show = Number.isFinite(maxShow) ? hits.slice(0, maxShow) : hits;
    const indent = 6;
    const ctxW = Math.max(8, innerW() - indent);
    for (const h of show) {
        boxRow(`  ${pc.dim(`[${h.start}:${h.end}]`)}  ${pc.bold(pc.green(`“${h.word}”`))}`, pc.green);
        const plainCtx = stripAnsi(h.contextLine);
        const ctxLines = wrapHardPlain(plainCtx, ctxW);
        const lineIdx = Math.floor(h.contextWordStart / ctxW);
        const colInLine = h.contextWordStart % ctxW;
        for (let li = 0; li < ctxLines.length; li++) {
            boxRow(" ".repeat(indent) + pc.dim(ctxLines[li]), pc.green);
            if (li === lineIdx) {
                boxRow(" ".repeat(indent + colInLine) + pc.magenta("^"), pc.green);
            }
        }
        if (ctxLines.length > 0 && lineIdx >= ctxLines.length) {
            boxRow(" ".repeat(indent + colInLine) + pc.magenta("^"), pc.green);
        }
    }
    if (hits.length > maxShow) {
        boxRow(pc.dim(`  … ${hits.length - maxShow} more (increase limit or see log file)`), pc.green);
    }
    boxBottom(pc.green);
    console.log("");
}
export function renderLogFooter(path) {
    console.log(pc.dim("  📄 Word positions & session log: ") + pc.white(pc.underline(path)));
    console.log("");
}
export function renderOutcomeBanner(solved) {
    if (solved) {
        boxTop(pc.green);
        boxRow(pc.bold(pc.green("  ✓  STRICT ENGLISH CHECK PASSED")), pc.green);
        boxRow(pc.dim("  Candidate treated as readable plaintext under dictionary + stats rules."), pc.green);
        boxBottom(pc.green);
    }
    else {
        boxTop(pc.yellow);
        boxRow(pc.bold(pc.yellow("  ◆  NO STRICT ENGLISH MATCH")), pc.yellow);
        boxRow(pc.dim("  The real method may differ (layering, non-alphanumeric key, non-XOR/Vigenère path)."), pc.yellow);
        boxBottom(pc.yellow);
    }
    console.log("");
}
export function renderCandidateCard(c, title) {
    boxTop(pc.magenta);
    boxRow(pc.bold(pc.magenta(`  ${title.toUpperCase()}`)), pc.magenta);
    boxMid(pc.magenta);
    const m = c.meta;
    if (m) {
        boxRow(lr(pc.dim("  Heuristic score"), pc.bold(pc.white(c.score.toFixed(2)))), pc.magenta);
        boxRow(lr(pc.dim("  χ² (letters)"), pc.white(m.chiSq.toFixed(1))), pc.magenta);
        boxRow(lr(pc.dim("  ASCII / letters"), pc.white(`${(m.printableRatio * 100).toFixed(0)}% / ${(m.letterRatio * 100).toFixed(0)}%`)), pc.magenta);
    }
    const detail = `${c.method}  │  ${c.detail}`;
    boxRow(pc.dim(`  ${detail}`), pc.magenta);
    boxMid(pc.magenta);
    const body = candidateBodyForDisplay(c.text);
    for (const line of wrapLines(body, innerW() - 2)) {
        boxRow(pc.white("  " + line), pc.magenta);
    }
    boxBottom(pc.magenta);
    console.log("");
}
export function renderReadabilityCard(r) {
    boxTop(pc.cyan);
    boxRow(pc.bold(pc.cyan("  READABILITY (STRICT GATE)")), pc.cyan);
    boxMid(pc.cyan);
    boxRow(lr(pc.dim("  ASCII ratio"), pc.white(`${(r.asciiRatio * 100).toFixed(1)}%`)), pc.cyan);
    boxRow(lr(pc.dim("  Letter ratio"), pc.white(`${(r.letterRatio * 100).toFixed(1)}%`)), pc.cyan);
    boxRow(lr(pc.dim("  Dictionary word hits"), pc.white(String(r.dictWordHits))), pc.cyan);
    boxRow(lr(pc.dim("  Token match ratio"), pc.white(`${(r.dictWordRatio * 100).toFixed(1)}%`)), pc.cyan);
    boxRow(lr(pc.dim("  χ²"), pc.white(r.chiSq.toFixed(1))), pc.cyan);
    boxRow(lr(pc.dim("  Quadgram density"), pc.white(r.quadgramHits.toFixed(5))), pc.cyan);
    if (!r.passes && r.reasons.length) {
        boxMid(pc.cyan);
        const reasons = r.reasons.join(", ");
        const wrapped = wrapLines(`Failures: ${reasons}`, innerW() - 2);
        for (const line of wrapped) {
            boxRow(pc.red("  " + line), pc.cyan);
        }
    }
    boxBottom(pc.cyan);
    console.log("");
}
function wrapLines(s, maxLen) {
    if (maxLen < 8)
        return [s];
    const words = s.split(/\s+/);
    const lines = [];
    let cur = "";
    for (const w of words) {
        if (!w.length)
            continue;
        if (w.length > maxLen) {
            if (cur) {
                lines.push(cur);
                cur = "";
            }
            for (let i = 0; i < w.length; i += maxLen) {
                lines.push(w.slice(i, i + maxLen));
            }
            continue;
        }
        const next = cur ? `${cur} ${w}` : w;
        if (next.length <= maxLen)
            cur = next;
        else {
            if (cur)
                lines.push(cur);
            cur = w;
        }
    }
    if (cur)
        lines.push(cur);
    return lines.length ? lines : [""];
}
function plainTruncate(s, n) {
    if (s.length <= n)
        return s;
    return `${s.slice(0, n)} … (${s.length - n} more chars)`;
}
// --- Legacy names (re-export thin wrappers for any internal use) ---
export const banner = (title) => {
    boxTop();
    boxRow(pc.bold(title));
    boxBottom();
};
export const section = (title) => {
    console.log(pc.bold(pc.yellow(`▸ ${title}`)));
    console.log(dimLine());
};
export const kv = (key, value, valueColor = pc.white) => {
    console.log(`  ${pc.dim(key.padEnd(22))} ${valueColor(value)}`);
};
export function statsBlock(opts) {
    renderStatsDashboard(opts);
}
export const phasesRow = renderPhasesPipeline;
export const wordHitsConsole = renderWordHits;
export const candidateBlock = renderCandidateCard;
export const readabilityBlock = renderReadabilityCard;
export const solvedBanner = () => renderOutcomeBanner(true);
export const unsolvedBanner = () => renderOutcomeBanner(false);
export const logFileNote = renderLogFooter;
