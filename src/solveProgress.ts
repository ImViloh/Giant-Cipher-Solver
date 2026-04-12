import pc from "picocolors";
import type { BruteProgressSnapshot } from "./bruteState.js";

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

function vigKeyspace(maxLen: number): number {
  return 2 * pow62Sum(maxLen);
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
      pc.cyan("nested B64, zlib, nibble swap, RC4, XOR") +
      pc.dim(" (solver layer-*)"),
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
