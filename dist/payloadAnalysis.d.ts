import { type HexPatternReport } from "./hexPatterns.js";
export type { HexPatternReport } from "./hexPatterns.js";
/** One detected wrapper or encoding on top of raw base64 output. */
export interface NestedFormatMatch {
    /** Short label for UI / logs, e.g. "Nested Base64". */
    kind: string;
    /** One-line explanation. */
    description: string;
    /** Truncated sample of what matched (string form). */
    detectedSample: string;
}
export interface ByteFingerprint {
    byteLength: number;
    /** Space-separated hex of first bytes. */
    hexHead: string;
    /** Optional tail hex if buffer is long and might matter. */
    hexTail?: string;
    /** Shannon entropy of the full buffer, bits per byte (0–8). */
    shannonEntropyBits: number;
    /** Ratio of bytes in 0x09,0x0a,0x0d,0x20–0x7e. */
    printableAsciiRatio: number;
    /** Inferred file / container types from magic bytes. */
    magicLabels: string[];
    /** Plain-language guesses (encryption-like vs structured file). */
    inferenceNotes: string[];
}
export interface PayloadAnalysisReport {
    matches: NestedFormatMatch[];
    fingerprint: ByteFingerprint;
    /** Structural hex / XOR / periodicity hints on raw decoded bytes. */
    hexPatterns: HexPatternReport;
}
/**
 * After standard base64 decode of the outer ciphertext, classify what the bytes
 * look like (nested encodings, PEM, JWT, magic files) and fingerprint raw bytes.
 */
export declare function analyzeDecodedPayload(buf: Buffer): PayloadAnalysisReport;
/** Plain-text block for giant-word-hits.log (or other append-only logs). */
export declare function formatPayloadAnalysisForLog(report: PayloadAnalysisReport): string;
