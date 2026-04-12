/**
 * English-likeness scoring for candidate plaintexts.
 * Combines chi-squared on A–Z frequencies, printable ratio, and common bigrams.
 */
export interface ScoreResult {
    score: number;
    chiSq: number;
    letterRatio: number;
    printableRatio: number;
    bigramBonus: number;
}
/**
 * Higher is better. Typical readable English: roughly -5 to 15+.
 * Garbage binary: large negative or very negative.
 */
export declare function scoreEnglish(text: string): ScoreResult;
export declare function bufferToPrintableUtf8(buf: Buffer): string | null;
export declare function bufferToLatin1(buf: Buffer): string;
