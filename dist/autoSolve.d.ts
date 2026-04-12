import { analyzeEnglishReadability } from "./englishReadability.js";
import { type Candidate } from "./solver.js";
export interface AutoSolveOptions {
    bruteMaxXorKeyLen: number;
    bruteMaxVigKeyLen: number;
    maxMs: number;
    progressEvery: number;
}
/** Resolved options (env) for UI preview before `runAutomaticSolve`. */
export declare function getPublicSolveOptions(): AutoSolveOptions;
export interface AutoSolveResult {
    solved: boolean;
    solution?: Candidate;
    readability?: ReturnType<typeof analyzeEnglishReadability>;
    nearMiss?: Candidate;
    xorKeysTried: number;
    vigKeysTried: number;
    xorTimedOut: boolean;
    vigTimedOut: boolean;
    phases: string[];
}
/**
 * 1) Heuristics (known keys + rotations + single-byte XOR, …).
 * 2) Full brute: repeating XOR with keys in [a-zA-Z0-9]^1..L on decoded bytes.
 * 3) Full brute: Vigenère + Beaufort on Base64 with same alphabet, key length 1..L.
 */
export declare function runAutomaticSolve(cipherB64: string, options?: Partial<AutoSolveOptions>): Promise<AutoSolveResult>;
