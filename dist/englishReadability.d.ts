/**
 * Strict checks for "readable English" to reduce false positives from random ASCII.
 * Uses a common-word set + letter/ASCII statistics (not a full NLP model).
 */
export declare const WORD_SET: Set<string>;
/** For word-position scanning (min length 3 to reduce noise). */
export declare function getDictionaryWordSet(): Set<string>;
export interface ReadabilityReport {
    passes: boolean;
    asciiRatio: number;
    letterRatio: number;
    dictWordHits: number;
    dictWordRatio: number;
    quadgramHits: number;
    chiSq: number;
    reasons: string[];
}
/**
 * True only if text looks like sustained English: mostly ASCII letters/spaces,
 * dictionary hits, letter distribution not absurd, quadgram-ish signal.
 */
export declare function isFullyEnglishReadable(text: string, minLen?: number): boolean;
export declare function analyzeEnglishReadability(text: string, minLen?: number): ReadabilityReport;
/** Higher = closer to English (for ranking when nothing passes strict gate). */
export declare function englishReadabilityRank(text: string): number;
