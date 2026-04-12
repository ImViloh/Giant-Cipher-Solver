/**
 * Live brute-force progress for SIGINT / SIGTERM reporting (and optional UI).
 * Updated from the main thread and worker tick messages.
 */

export type BrutePhase =
  | "idle"
  | "heuristics"
  | "xor"
  | "vig"
  | "done";

export interface BruteProgressSnapshot {
  phase: BrutePhase;
  xorKeyLen: number;
  /** Best-effort cumulative XOR keys tried (includes partial ticks during parallel batches). */
  xorTried: number;
  vigMode: "vigenere-b64" | "beaufort-b64" | "";
  vigKeyLen: number;
  vigTried: number;
}

const snap: BruteProgressSnapshot = {
  phase: "idle",
  xorKeyLen: 0,
  xorTried: 0,
  vigMode: "",
  vigKeyLen: 0,
  vigTried: 0,
};

export function resetBruteProgress(): void {
  snap.phase = "idle";
  snap.xorKeyLen = 0;
  snap.xorTried = 0;
  snap.vigMode = "";
  snap.vigKeyLen = 0;
  snap.vigTried = 0;
}

export function setBruteProgress(p: Partial<BruteProgressSnapshot>): void {
  if (p.phase !== undefined) snap.phase = p.phase;
  if (p.xorKeyLen !== undefined) snap.xorKeyLen = p.xorKeyLen;
  if (p.xorTried !== undefined) snap.xorTried = p.xorTried;
  if (p.vigMode !== undefined) snap.vigMode = p.vigMode;
  if (p.vigKeyLen !== undefined) snap.vigKeyLen = p.vigKeyLen;
  if (p.vigTried !== undefined) snap.vigTried = p.vigTried;
}

export function getBruteProgressSnapshot(): BruteProgressSnapshot {
  return { ...snap };
}
