/**
 * Heuristic hex / binary structure analysis on decoded ciphertext to surface
 * patterns that suggest next cryptanalysis steps (XOR, ECB, periodicity, etc.).
 */
export interface HexPatternFind {
    /** Short heading for UI. */
    title: string;
    /** What we observed. */
    detail: string;
    /** Concrete next step or interpretation. */
    suggest?: string;
}
export interface HexDumpLine {
    offset: string;
    hex: string;
    ascii: string;
}
export interface XorPrintableHint {
    keyByte: number;
    /** Fraction of bytes in 0x20–0x7e after XOR (excluding tab/lf). */
    printableRatio: number;
}
export interface HexPatternReport {
    annotatedLines: HexDumpLine[];
    finds: HexPatternFind[];
    uniqueByteValues: number;
    topBytes: {
        hex: string;
        count: number;
        pct: number;
    }[];
    xorHints: XorPrintableHint[];
}
/** Shown in UI / log as annotated hex (first N bytes). */
export declare const HEX_PATTERN_PREVIEW_BYTES = 128;
/**
 * Structural / statistical scan of raw bytes after Base64 decode.
 */
export declare function analyzeHexPatterns(buf: Buffer): HexPatternReport;
