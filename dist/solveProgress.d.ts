import type { BruteProgressSnapshot } from "./bruteState.js";
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
