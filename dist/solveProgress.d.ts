import { type BruteProgressSnapshot } from "./bruteState.js";
export declare function vigKeyspace(maxLen: number): number;
/** Total XOR keys tried for lengths 1…maxLen (matches `bruteXorAlphanumeric`). */
export declare function totalXorKeyspace(maxLen: number): number;
/** Total Vigenère + Beaufort keys for lengths 1…maxLen (matches `bruteVigenereB64Alphanumeric`). */
export declare function totalVigKeyspace(maxLen: number): number;
/**
 * Yellow boxed live progress (keys, bar, budget countdown, ETA). Polls `getBruteProgressSnapshot`.
 * No-op when stdout is not a TTY. Call `stopBruteLiveUi` when XOR+VIG complete.
 */
export declare function startBruteLiveUi(opts: {
    xorMaxLen: number;
    vigMaxLen: number;
    maxMs: number;
    xorPhaseStartedAt: number;
}): void;
/** Call immediately before `bruteVigenereB64Alphanumeric` so budget + ETA use the VIG phase clock. */
export declare function markVigBrutePhaseStart(): void;
export declare function stopBruteLiveUi(): void;
/**
 * Shown **before** heavy work so the terminal never looks “empty” during long brute phases.
 */
export declare function printPreSolveBanner(opts: {
    xorMaxLen: number;
    vigMaxLen: number;
    maxMs: number;
    progressEvery: number;
    /** Worker threads used for large XOR / Vigenère ranges (GIANT_THREADS). */
    workerThreads: number;
}): void;
/** Printed after brute phases finish, before the main dashboard. */
export declare function printSolveCompleteSeparator(): void;
/** Styled progress line (stdout) — matches dashboard vibe. */
export declare function printXorBruteProgress(phase: string, tried: number, keyLen: number): void;
export declare function printVigBruteProgress(phase: string, tried: number): void;
/** On SIGINT/SIGTERM during brute phases — shows last known key-space progress. */
export declare function printInterruptedProgress(snap: BruteProgressSnapshot, signal: string): void;
