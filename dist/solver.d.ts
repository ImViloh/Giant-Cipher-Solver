import { type ScoreResult } from "./scoring.js";
export interface CipherInput {
    cipher: string;
}
export interface Candidate {
    method: string;
    detail: string;
    text: string;
    score: number;
    meta?: ScoreResult;
}
export declare function loadCipherJson(path: string): CipherInput;
/**
 * Run every implemented heuristic / brute step and collect scored candidates.
 */
export declare function solveCipherString(cipherB64: string): Candidate[];
export declare function defaultCipherPath(): string;
export declare function dedupeAndSort(candidates: Candidate[]): Candidate[];
