/**
 * Human-readable catalog of cipher methods this tool exercises (COD Zombies–aligned
 * plus standard cryptanalysis). Displayed in the boxed CLI UI.
 */
export interface CodCipherSuiteSection {
    title: string;
    /** Bullet lines (method id or family → short note). */
    lines: string[];
}
export declare const COD_CIPHER_SUITE_SECTIONS: CodCipherSuiteSection[];
