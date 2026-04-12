/**
 * Live brute-force progress for SIGINT / SIGTERM reporting (and optional UI).
 * Updated from the main thread and worker tick messages.
 */
export type BrutePhase = "idle" | "heuristics" | "xor" | "vig" | "done";
export interface BruteProgressSnapshot {
    phase: BrutePhase;
    xorKeyLen: number;
    /** Best-effort cumulative XOR keys tried (includes partial ticks during parallel batches). */
    xorTried: number;
    vigMode: "vigenere-b64" | "beaufort-b64" | "";
    vigKeyLen: number;
    vigTried: number;
}
export declare function resetBruteProgress(): void;
export declare function setBruteProgress(p: Partial<BruteProgressSnapshot>): void;
export declare function getBruteProgressSnapshot(): BruteProgressSnapshot;
