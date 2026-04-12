export { ALPHANUM62 } from "./keyspace.js";
/** `maxMs <= 0` means no time limit (practical infinity). */
export declare function bruteDeadline(t0: number, maxMs: number): number;
export declare function getWorkerThreadCount(): number;
export interface BruteXorResult {
    key: string;
    text: string;
}
export interface BruteXorOutcome {
    hit: BruteXorResult | null;
    tried: number;
    timedOut: boolean;
}
/**
 * Enumerate every repeating XOR key over [a-zA-Z0-9] up to maxKeyLen.
 * Uses worker threads for large keyspaces per length.
 */
export declare function bruteXorAlphanumeric(decoded: Buffer, maxKeyLen: number, maxMs: number, onProgress?: (phase: string, tried: number, keyLen: number) => void): Promise<BruteXorOutcome>;
export interface BruteVigResult {
    key: string;
    text: string;
    mode: "vigenere-b64" | "beaufort-b64";
}
export interface BruteVigOutcome {
    hit: BruteVigResult | null;
    tried: number;
    timedOut: boolean;
}
/**
 * Brute Vigenère / Beaufort on Base64 layer with alphanumeric keys.
 */
export declare function bruteVigenereB64Alphanumeric(cipherB64: string, maxKeyLen: number, maxMs: number, onProgress?: (phase: string, tried: number) => void): Promise<BruteVigOutcome>;
/** Best Latin-1 string by readability rank (for reporting when nothing passes). */
export declare function rankLatin1Text(text: string): number;
