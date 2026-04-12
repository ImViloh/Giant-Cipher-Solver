import * as readline from "node:readline";
import pc from "picocolors";
import {
  getBruteProgressSnapshot,
  type BruteProgressSnapshot,
} from "./bruteState.js";

function stripAnsi(s: string): string {
  return s.replace(/\u001b\[[\d;]*m/g, "");
}

function pow62Sum(maxLen: number): number {
  let t = 0;
  let p = 1;
  const n = 62;
  for (let i = 0; i < maxLen; i++) {
    p *= n;
    t += p;
  }
  return t;
}

export function vigKeyspace(maxLen: number): number {
  return 2 * pow62Sum(maxLen);
}

/** Total XOR keys tried for lengths 1…maxLen (matches `bruteXorAlphanumeric`). */
export function totalXorKeyspace(maxLen: number): number {
  return pow62Sum(maxLen);
}

/** Total Vigenère + Beaufort keys for lengths 1…maxLen (matches `bruteVigenereB64Alphanumeric`). */
export function totalVigKeyspace(maxLen: number): number {
  return vigKeyspace(maxLen);
}

const LIVE_W = 84;
const LIVE_TICK_MS = 350;

let bruteLiveTimer: NodeJS.Timeout | null = null;
let bruteLiveLineCount = 0;
let bruteLiveFirstDraw = true;

interface BruteLiveOpts {
  xorTotal: number;
  vigTotal: number;
  maxMs: number;
  xorPhaseStartedAt: number;
  vigPhaseStartedAt: number | null;
}

let bruteLiveOpts: BruteLiveOpts | null = null;

function formatDurationSec(sec: number): string {
  if (!Number.isFinite(sec) || sec < 0) return "—";
  if (sec >= 86400 * 2) return "≫48h";
  const s = Math.floor(sec % 60);
  const m = Math.floor((sec / 60) % 60);
  const h = Math.floor(sec / 3600);
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

function barMeterPct(pct: number, width: number): string {
  const p = Math.max(0, Math.min(100, pct));
  const filled = Math.round((p / 100) * width);
  return (
    pc.green("█".repeat(filled)) +
    pc.dim("░".repeat(Math.max(0, width - filled))) +
    pc.dim(" ") +
    pc.bold(pc.white(p.toFixed(1))) +
    pc.dim("%")
  );
}

function buildBruteLiveLines(now: number): string[] {
  const o = bruteLiveOpts;
  if (!o) return [];
  const snap = getBruteProgressSnapshot();
  const xorT = snap.xorTried;
  const vigT = snap.vigTried;
  const combinedDone = xorT + vigT;
  const combinedTotal = o.xorTotal + o.vigTotal;
  const pct =
    combinedTotal > 0
      ? Math.min(100, (100 * combinedDone) / combinedTotal)
      : 0;

  let phaseLine = pc.dim("  Phase: ");
  if (snap.phase === "xor") {
    phaseLine +=
      pc.magenta("XOR") +
      pc.dim(" · key length ") +
      pc.cyan(String(snap.xorKeyLen || 1));
  } else if (snap.phase === "vig") {
    const mode =
      snap.vigMode === "beaufort-b64"
        ? "Beaufort"
        : snap.vigMode === "vigenere-b64"
          ? "Vigenère"
          : "Base64";
    phaseLine +=
      pc.magenta(mode) +
      pc.dim(" · key length ") +
      pc.cyan(String(snap.vigKeyLen || 1));
  } else {
    phaseLine += pc.dim("(starting…)");
  }

  const phaseStart =
    snap.phase === "vig" && o.vigPhaseStartedAt != null
      ? o.vigPhaseStartedAt
      : o.xorPhaseStartedAt;
  const phaseElapsedSec = Math.max(0, (now - phaseStart) / 1000);
  const phaseTried = snap.phase === "vig" ? vigT : xorT;
  const phaseTotal =
    snap.phase === "vig" ? o.vigTotal : o.xorTotal;
  const phaseLeft = Math.max(0, phaseTotal - phaseTried);

  let budgetStr = pc.dim("no wall limit");
  if (o.maxMs > 0) {
    const leftMs = Math.max(0, o.maxMs - (now - phaseStart));
    budgetStr =
      pc.yellow(formatDurationSec(leftMs / 1000)) +
      pc.dim(" left in phase budget");
  }

  let etaStr = pc.dim("ETA: —");
  if (phaseTried >= 2000 && phaseElapsedSec > 0.5 && phaseLeft > 0) {
    const rate = phaseTried / phaseElapsedSec;
    if (rate > 0) {
      const etaSec = phaseLeft / rate;
      etaStr =
        pc.cyan("ETA ") +
        pc.white("~") +
        pc.bold(pc.cyan(formatDurationSec(etaSec))) +
        pc.dim(" (this phase, linear)");
    }
  }

  const keysLine =
    pc.dim("  Keys  ") +
    pc.white(phaseTried.toLocaleString()) +
    pc.dim(" tried  ·  ") +
    pc.white(phaseLeft.toLocaleString()) +
    pc.dim(" left (this phase)  │  pipeline ") +
    pc.white(combinedDone.toLocaleString()) +
    pc.dim(" / ") +
    pc.white(combinedTotal.toLocaleString());

  const timeLine =
    pc.dim("  Time  ") +
    budgetStr +
    pc.dim("  │  ") +
    etaStr +
    pc.dim("  │  phase elapsed ") +
    pc.white(formatDurationSec(phaseElapsedSec));

  const barInner = 58;
  const barRow =
    pc.dim("  ") + barMeterPct(pct, barInner) + pc.dim("  pipeline");

  const top = pc.yellow("╔" + "═".repeat(LIVE_W - 2) + "╗");
  const mid = pc.yellow("╠" + "═".repeat(LIVE_W - 2) + "╣");
  const bot = pc.yellow("╚" + "═".repeat(LIVE_W - 2) + "╝");

  const row = (inner: string): string =>
    pc.yellow("║") +
    " " +
    inner +
    " ".repeat(Math.max(0, LIVE_W - 4 - stripAnsi(inner).length)) +
    " " +
    pc.yellow("║");

  return [
    top,
    row(pc.bold(pc.yellow("  LIVE BRUTE PROGRESS"))),
    mid,
    row(phaseLine),
    row(barRow),
    row(keysLine),
    row(timeLine),
    bot,
  ];
}

function redrawBruteLive(lines: string[]): void {
  if (bruteLiveFirstDraw) {
    for (const line of lines) console.log(line);
    bruteLiveFirstDraw = false;
    bruteLiveLineCount = lines.length;
    return;
  }
  readline.moveCursor(process.stdout, 0, -bruteLiveLineCount);
  for (const line of lines) {
    readline.cursorTo(process.stdout, 0);
    readline.clearLine(process.stdout, 0);
    console.log(line);
  }
}

/**
 * Yellow boxed live progress (keys, bar, budget countdown, ETA). Polls `getBruteProgressSnapshot`.
 * No-op when stdout is not a TTY. Call `stopBruteLiveUi` when XOR+VIG complete.
 */
export function startBruteLiveUi(opts: {
  xorMaxLen: number;
  vigMaxLen: number;
  maxMs: number;
  xorPhaseStartedAt: number;
}): void {
  stopBruteLiveUi();
  if (!process.stdout.isTTY) return;

  bruteLiveOpts = {
    xorTotal: totalXorKeyspace(opts.xorMaxLen),
    vigTotal: totalVigKeyspace(opts.vigMaxLen),
    maxMs: opts.maxMs,
    xorPhaseStartedAt: opts.xorPhaseStartedAt,
    vigPhaseStartedAt: null,
  };
  bruteLiveFirstDraw = true;

  const tick = (): void => {
    if (!bruteLiveOpts) return;
    redrawBruteLive(buildBruteLiveLines(Date.now()));
  };
  tick();
  bruteLiveTimer = setInterval(tick, LIVE_TICK_MS);
}

/** Call immediately before `bruteVigenereB64Alphanumeric` so budget + ETA use the VIG phase clock. */
export function markVigBrutePhaseStart(): void {
  if (bruteLiveOpts) {
    bruteLiveOpts.vigPhaseStartedAt = Date.now();
  }
}

export function stopBruteLiveUi(): void {
  if (bruteLiveTimer) {
    clearInterval(bruteLiveTimer);
    bruteLiveTimer = null;
  }
  const hadPanel = bruteLiveOpts !== null && process.stdout.isTTY;
  if (hadPanel && bruteLiveLineCount > 0 && !bruteLiveFirstDraw) {
    redrawBruteLive(buildBruteLiveLines(Date.now()));
  }
  bruteLiveOpts = null;
  bruteLiveFirstDraw = true;
  bruteLiveLineCount = 0;
  if (hadPanel) console.log("");
}

/**
 * Shown **before** heavy work so the terminal never looks “empty” during long brute phases.
 */
export function printPreSolveBanner(opts: {
  xorMaxLen: number;
  vigMaxLen: number;
  maxMs: number;
  progressEvery: number;
  /** Worker threads used for large XOR / Vigenère ranges (GIANT_THREADS). */
  workerThreads: number;
}): void {
  const xorKeys = pow62Sum(opts.xorMaxLen).toLocaleString();
  const vigKeys = vigKeyspace(opts.vigMaxLen).toLocaleString();
  const W = 84;
  const top = pc.yellow("╔" + "═".repeat(W - 2) + "╗");
  const mid = pc.yellow("╠" + "═".repeat(W - 2) + "╣");
  const bot = pc.yellow("╚" + "═".repeat(W - 2) + "╝");
  const row = (s: string) =>
    console.log(
      pc.yellow("║") +
        " " +
        s +
        " ".repeat(Math.max(0, W - 4 - stripAnsi(s).length)) +
        " " +
        pc.yellow("║"),
    );

  console.log("");
  console.log(top);
  row(pc.bold(pc.yellow("  CRYPTANALYSIS RUNNING")));
  console.log(mid);
  row(pc.dim("  The full colored dashboard appears ") + pc.white("after") + pc.dim(" this step finishes."));
  row(
    pc.dim("  Parallel workers (brute ranges) ") +
      pc.cyan(String(opts.workerThreads)) +
      pc.dim("  (set GIANT_THREADS to cap; 1 = single-threaded)"),
  );
  row(pc.dim("  XOR brute search space (len 1…" + opts.xorMaxLen + "): ~" + xorKeys + " keys"));
  row(pc.dim("  Vigenère+Beaufort on Base64 (len 1…" + opts.vigMaxLen + "): ~" + vigKeys + " keys"));
  row(
    pc.dim("  Layered probes: ") +
      pc.cyan(
        "classical A26/A52, AES/3DES/RC2*/BF*, nested B64, zlib, nibble, RC4, XOR",
      ) +
      pc.dim(" (extended + layer-*)"),
  );
  row(
    pc.dim("  Time budget (brute phases): ") +
      (opts.maxMs <= 0
        ? pc.cyan("unlimited") + pc.dim(" (GIANT_MAX_MS=0)")
        : pc.cyan(`${(opts.maxMs / 1000).toFixed(0)}s`)),
  );
  if (opts.progressEvery > 0) {
    row(
      pc.dim("  Progress update every ") +
        pc.cyan(`~${opts.progressEvery.toLocaleString()}`) +
        pc.dim(" XOR tries (GIANT_PROGRESS_EVERY)"),
    );
  } else {
    row(pc.dim("  Live XOR progress: ") + pc.cyan("off") + pc.dim(" (GIANT_PROGRESS_EVERY=0)"));
  }
  row(
    pc.dim("  Yellow ") +
      pc.cyan("live brute") +
      pc.dim(" box: keys, bar, phase budget countdown, ETA (TTY only)."),
  );
  row(pc.dim("  Tip: ") + pc.white("npm run solve:quick") + pc.dim(" for a shorter run while testing."));
  console.log(bot);
  console.log("");
}

/** Printed after brute phases finish, before the main dashboard. */
export function printSolveCompleteSeparator(): void {
  console.log("");
  console.log(pc.dim("  " + "─".repeat(80)));
  console.log(
    pc.bold(pc.cyan("  ✓  Cryptanalysis step finished  →  full report below")),
  );
  console.log(pc.dim("  " + "─".repeat(80)));
  console.log("");
}

/** Styled progress line (stdout) — matches dashboard vibe. */
export function printXorBruteProgress(
  phase: string,
  tried: number,
  keyLen: number,
): void {
  const pct =
    keyLen > 0
      ? pc.cyan(`key length ${keyLen}`)
      : "";
  const n = tried.toLocaleString();
  console.log(
    pc.dim("  ⟳ ") +
      pc.magenta("XOR brute") +
      "  " +
      pct +
      "  " +
      pc.dim("·") +
      "  " +
      pc.white(`~${n}`) +
      pc.dim(" keys tried") +
      "  " +
      pc.dim(`(${phase})`),
  );
}

export function printVigBruteProgress(phase: string, tried: number): void {
  console.log(
    pc.dim("  ⟳ ") +
      pc.magenta("Base64 " + phase) +
      "  " +
      pc.dim("·") +
      "  " +
      pc.white(`~${tried.toLocaleString()}`) +
      pc.dim(" keys tried"),
  );
}

/** On SIGINT/SIGTERM during brute phases — shows last known key-space progress. */
export function printInterruptedProgress(
  snap: BruteProgressSnapshot,
  signal: string,
): void {
  const W = 84;
  const top = pc.red("╔" + "═".repeat(W - 2) + "╗");
  const mid = pc.red("╠" + "═".repeat(W - 2) + "╣");
  const bot = pc.red("╚" + "═".repeat(W - 2) + "╝");
  const row = (s: string) =>
    console.log(
      pc.red("║") +
        " " +
        s +
        " ".repeat(Math.max(0, W - 4 - stripAnsi(s).length)) +
        " " +
        pc.red("║"),
    );

  console.log("");
  console.log(top);
  row(
    pc.bold(pc.red("  INTERRUPTED (" + signal + ") — last brute-force progress")),
  );
  console.log(mid);
  row(
    pc.dim("  Phase: ") +
      pc.white(snap.phase) +
      (snap.phase === "xor"
        ? pc.dim("  ·  XOR key length ") + pc.cyan(String(snap.xorKeyLen))
        : "") +
      (snap.phase === "vig"
        ? pc.dim("  ·  ") +
          pc.white(snap.vigMode) +
          pc.dim(" key length ") +
          pc.cyan(String(snap.vigKeyLen))
        : ""),
  );
  row(
    pc.dim("  XOR keys tried (cumulative): ") +
      pc.yellow(snap.xorTried.toLocaleString()),
  );
  row(
    pc.dim("  Vigenère/Beaufort keys tried (cumulative): ") +
      pc.yellow(snap.vigTried.toLocaleString()),
  );
  row(
    pc.dim(
      "  Tip: re-run with the same env; progress is not saved to disk.",
    ),
  );
  console.log(bot);
  console.log("");
}
