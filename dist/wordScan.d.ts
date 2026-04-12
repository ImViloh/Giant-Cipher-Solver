export interface WordHit {
    /** Matched word (lowercase). */
    word: string;
    /** Inclusive start index in the analyzed string. */
    start: number;
    /** Exclusive end index. */
    end: number;
    /** Snippet around the match (newlines shown as ↵). */
    contextLine: string;
    /** Character offset in contextLine where the word begins (for marking). */
    contextWordStart: number;
}
/**
 * Find dictionary English words in plaintext as letter-only tokens (A–Z / a–z),
 * with character indices into `text`.
 */
export declare function scanForDictionaryWords(text: string, minWordLen?: number, dict?: Set<string>): WordHit[];
export interface WordLogSectionMeta {
    sourceLabel: string;
    plaintextLength: number;
    method?: string;
    detail?: string;
}
export interface SessionWordLogMeta {
    timestamp: string;
    durationMs: number;
    cipherBase64Length: number;
}
/** Default log path in cwd; override with GIANT_WORD_LOG. */
export declare function defaultWordLogPath(cwd?: string): string;
/**
 * One run = one file: ciphertext string + each analyzed plaintext section with positions.
 */
export declare function writeSessionWordLog(path: string, session: SessionWordLogMeta, sections: Array<WordLogSectionMeta & {
    text: string;
}>): void;
/** Append a single section (optional tooling). */
export declare function appendWordHitsSection(path: string, meta: WordLogSectionMeta, hits: WordHit[]): void;
