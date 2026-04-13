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
    /** How many leading bytes are covered by `annotatedLines` (after cap). */
    bytesAnnotated: number;
    finds: HexPatternFind[];
    uniqueByteValues: number;
    topBytes: {
        hex: string;
        count: number;
        pct: number;
    }[];
    xorHints: XorPrintableHint[];
}
/** Default cap for annotated hex when `GIANT_HEX_DUMP_BYTES` is unset. */
export declare const HEX_PATTERN_PREVIEW_BYTES = 8192;
/** Bytes to include in annotated hex dump (env `GIANT_HEX_DUMP_BYTES`, default 8192; `0` or `full` = up to 1 MiB). */
export declare function hexDumpByteLimit(bufLen: number): number;
/**
 * Structural / statistical scan of raw bytes after Base64 decode.
 */
export declare function analyzeHexPatterns(buf: Buffer): HexPatternReport;
