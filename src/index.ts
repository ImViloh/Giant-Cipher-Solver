#!/usr/bin/env node
/**
 * Giant Cipher solver — BO3 The Giant unsolved cipher (cipherbase.json).
 * Default: automatic search until strict English is found or brute keyspaces end.
 * Use --dump-all for the legacy full candidate list.
 */
import { appendFileSync } from "node:fs";
import { resolve } from "node:path";
import { getWorkerThreadCount } from "./bruteforce.js";
import { getBruteProgressSnapshot, setBruteProgress } from "./bruteState.js";
import { getPublicSolveOptions, runAutomaticSolve } from "./autoSolve.js";
import { analyzeEnglishReadability } from "./englishReadability.js";
import {
  renderCandidateCard,
  renderDumpIntro,
  renderHero,
  renderInputStrip,
  renderLogFooter,
  renderHexPatternPanel,
  renderPayloadAnalysis,
  renderPhasesPipeline,
  renderReadabilityCard,
  renderStatsDashboard,
  renderWordHits,
  section,
} from "./consoleUi.js";
import {
  analyzeDecodedPayload,
  formatPayloadAnalysisForLog,
} from "./payloadAnalysis.js";
import {
  estimatePlausibilityPercent,
  summarizeCandidatePool,
} from "./stats.js";
import {
  dedupeAndSort,
  loadCipherJson,
  solveCipherString,
  defaultCipherPath,
  type Candidate,
} from "./solver.js";
import { safeBase64Decode } from "./transforms.js";
import {
  printInterruptedProgress,
  printPreSolveBanner,
  printSolveCompleteSeparator,
} from "./solveProgress.js";
import {
  defaultWordLogPath,
  scanForDictionaryWords,
  writeSessionWordLog,
} from "./wordScan.js";

function parseArgs(argv: string[]): {
  jsonPath: string;
  minScore: number;
  limit: number;
  jsonl: boolean;
  dumpAll: boolean;
} {
  let jsonPath = resolve(defaultCipherPath());
  let minScore = Number.NEGATIVE_INFINITY;
  let limit = Number.POSITIVE_INFINITY;
  let jsonl = false;
  let dumpAll = false;

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--file" || a === "-f") {
      jsonPath = resolve(argv[++i] ?? "");
    } else if (a === "--min-score") {
      minScore = Number(argv[++i]);
    } else if (a === "--limit" || a === "-n") {
      limit = Number(argv[++i]);
    } else if (a === "--jsonl") {
      jsonl = true;
    } else if (a === "--dump-all" || a === "--legacy") {
      dumpAll = true;
    } else if (a === "--help" || a === "-h") {
      console.log(`
Usage: node dist/index.js [options]

  Default mode runs heuristics, then full alphanumeric brute-force on XOR and
  Base64 Vigenère/Beaufort until readable English is found or limits are hit.

  -f, --file <path>   JSON with { "cipher": "<base64>" } (default: ../cipherbase.json)
  --dump-all          Legacy: list every scored candidate (no auto brute loop)
  --min-score <n>     With --dump-all: floor on heuristic score
  -n, --limit <n>     With --dump-all: max rows
  --jsonl             With --dump-all: one JSON object per line

Environment (auto / brute):
  GIANT_MAX_MS          Wall time for brute phases in ms (default 600000 = 10 min).
                        Use 0 for unlimited (until you Ctrl+C — progress is printed on exit).
  GIANT_BRUTE_XOR_LEN   Max repeating XOR key length over [a-zA-Z0-9] (default 4; no hard cap — warns if >3)
  GIANT_BRUTE_VIG_LEN   Max Vigenère/Beaufort key length on Base64 (default 3; no hard cap — warns if >3)
  GIANT_PROGRESS_EVERY  Log XOR progress every N tries (default 250000; 0 = off)
  GIANT_EXTRA_KEYS      Extra comma-separated keys for heuristic phase only
  GIANT_WORD_LOG        Path for dictionary word hit log (default ./giant-word-hits.log)
  GIANT_THREADS         Worker threads for brute-force (default: CPU count; 1 = disable parallelism)

Extended probes (heuristic candidate pool — disable to speed up):
  GIANT_EXTENDED_PROBES       0 = skip classical + block-cipher + cumulative-XOR probes (default 1)
  GIANT_CLASSICAL_PROBES      0 = skip Beaufort/Vigenère/rail/atbash/Caesar (default 1)
  GIANT_BLOCK_CIPHER_PROBES   0 = skip OpenSSL AES/3DES/RC2/BF tries (default 1)
  GIANT_EXTENDED_KEYWORDS     Max keyword list size for classical + block (default 120)
  GIANT_CLASSICAL_KEYS        Max keywords for classical ciphers only (default 80)
  GIANT_BLOCK_CIPHER_KEYS     Max passphrases for block ciphers (default 48)
  GIANT_BLOCK_CIPHER_MAX      Max successful block decrypts per direction (default 80)
`);
      process.exit(0);
    }
  }

  return { jsonPath, minScore, limit, jsonl, dumpAll };
}

function formatLine(rank: number, c: Candidate): string {
  const m = c.meta;
  const metaStr = m
    ? ` chi²=${m.chiSq.toFixed(1)} print=${(m.printableRatio * 100).toFixed(0)}% letters=${(m.letterRatio * 100).toFixed(0)}%`
    : "";
  return (
    `[${rank}] score=${c.score.toFixed(2)} | ${c.method} | ${c.detail}${metaStr}\n` +
    `    TEXT: ${truncateForDisplay(c.text)}`
  );
}

function truncateForDisplay(s: string, max = 2000): string {
  if (s.length <= max) return s;
  return s.slice(0, max) + `\n    ... (${s.length - max} more chars)`;
}

function runLegacyDump(
  jsonPath: string,
  raw: string,
  minScore: number,
  limit: number,
  jsonl: boolean,
): void {
  const candidates = dedupeAndSort(solveCipherString(raw));
  const filtered = candidates.filter((c) => c.score >= minScore);
  const toShow =
    Number.isFinite(limit) && limit < filtered.length
      ? filtered.slice(0, limit)
      : filtered;

  if (jsonl) {
    for (const c of filtered) {
      console.log(
        JSON.stringify({
          method: c.method,
          detail: c.detail,
          score: c.score,
          chiSq: c.meta?.chiSq,
          text: c.text,
        }),
      );
    }
    return;
  }

  renderDumpIntro({
    inputPath: jsonPath,
    base64Length: raw.length,
    totalCandidates: candidates.length,
    afterFilter: filtered.length,
  });

  let rank = 1;
  for (const c of toShow) {
    console.log(formatLine(rank, c));
    console.log("");
    rank++;
  }

  const best = filtered[0];
  if (best) {
    console.log("");
    section("Best heuristic score");
    console.log(formatLine(1, best));
  }
}

function installInterruptProgressHandlers(): void {
  let once = false;
  const stop = (sig: NodeJS.Signals) => {
    if (once) return;
    once = true;
    console.log("");
    printInterruptedProgress(getBruteProgressSnapshot(), sig);
    process.exit(sig === "SIGINT" ? 130 : 143);
  };
  process.on("SIGINT", () => stop("SIGINT"));
  process.on("SIGTERM", () => stop("SIGTERM"));
}

async function main(): Promise<void> {
  const { jsonPath, minScore, limit, jsonl, dumpAll } = parseArgs(
    process.argv.slice(2),
  );

  installInterruptProgressHandlers();

  const input = loadCipherJson(jsonPath);
  const raw = input.cipher.trim();

  if (dumpAll) {
    const decDump = safeBase64Decode(raw);
    const reportDump = decDump ? analyzeDecodedPayload(decDump) : null;
    runLegacyDump(jsonPath, raw, minScore, limit, jsonl);
    if (reportDump) {
      renderPayloadAnalysis(reportDump);
      renderHexPatternPanel(reportDump.hexPatterns);
    } else {
      section("Outer Base64");
      console.log("  (decode failed — skipping payload fingerprint)");
      console.log("");
    }
    return;
  }

  const previewOpts = getPublicSolveOptions();
  printPreSolveBanner({
    xorMaxLen: previewOpts.bruteMaxXorKeyLen,
    vigMaxLen: previewOpts.bruteMaxVigKeyLen,
    maxMs: previewOpts.maxMs,
    progressEvery: previewOpts.progressEvery,
    workerThreads: getWorkerThreadCount(),
  });

  const t0 = performance.now();
  const result = await runAutomaticSolve(raw);
  const elapsedMs = performance.now() - t0;

  setBruteProgress({ phase: "done" });

  printSolveCompleteSeparator();
  const allCandidates = dedupeAndSort(solveCipherString(raw));
  const pool = summarizeCandidatePool(allCandidates);

  const nearReadability = result.nearMiss
    ? analyzeEnglishReadability(result.nearMiss.text)
    : undefined;
  const plausibility = estimatePlausibilityPercent(
    result.solved,
    result.readability ?? nearReadability,
    result.nearMiss,
  );

  const logPath = defaultWordLogPath();
  const ts = new Date().toISOString();
  const sections: Array<{
    sourceLabel: string;
    plaintextLength: number;
    method?: string;
    detail?: string;
    text: string;
  }> = [
    {
      sourceLabel: "Base64 ciphertext (stored string, character indices)",
      plaintextLength: raw.length,
      text: raw,
    },
  ];
  if (result.solution) {
    sections.push({
      sourceLabel: "Auto-solve best / solution candidate",
      plaintextLength: result.solution.text.length,
      method: result.solution.method,
      detail: result.solution.detail,
      text: result.solution.text,
    });
  } else if (result.nearMiss) {
    sections.push({
      sourceLabel: "Best near-miss (heuristic English rank)",
      plaintextLength: result.nearMiss.text.length,
      method: result.nearMiss.method,
      detail: result.nearMiss.detail,
      text: result.nearMiss.text,
    });
  }
  writeSessionWordLog(
    logPath,
    {
      timestamp: ts,
      durationMs: elapsedMs,
      cipherBase64Length: raw.length,
    },
    sections,
  );

  const outerDecoded = safeBase64Decode(raw);
  const payloadReport = outerDecoded ? analyzeDecodedPayload(outerDecoded) : null;
  if (payloadReport) {
    appendFileSync(logPath, formatPayloadAnalysisForLog(payloadReport), "utf8");
  }

  renderHero(result.solved);
  renderInputStrip({ inputPath: jsonPath, base64Length: raw.length });

  if (payloadReport) {
    renderPayloadAnalysis(payloadReport);
    renderHexPatternPanel(payloadReport.hexPatterns);
  }

  renderStatsDashboard({
    elapsedMs,
    plausibilityPercent: plausibility,
    solved: result.solved,
    pool,
    xorTried: result.xorKeysTried,
    vigTried: result.vigKeysTried,
    xorTimeout: result.xorTimedOut,
    vigTimeout: result.vigTimedOut,
    topTierDelta: 25,
    plausibleFloor: -35,
  });

  renderPhasesPipeline(result.phases);

  const primaryText = result.solution?.text ?? result.nearMiss?.text ?? "";
  const primaryHits = primaryText
    ? scanForDictionaryWords(primaryText)
    : [];
  renderWordHits(primaryHits);

  renderLogFooter(logPath);

  if (result.solved && result.solution) {
    renderCandidateCard(result.solution, "Solution");
    if (result.readability) {
      renderReadabilityCard(result.readability);
    }
    return;
  }

  if (result.nearMiss) {
    renderCandidateCard(result.nearMiss, "Best near-miss");
    renderReadabilityCard(
      nearReadability ?? analyzeEnglishReadability(result.nearMiss.text),
    );
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
