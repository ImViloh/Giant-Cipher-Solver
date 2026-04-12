/**
 * Classical polyalphabetic / transposition ciphers on text.
 * Revelations-style solves often use Beaufort + keyword (e.g. ZOMBIES) with A–Z then a–z as one alphabet.
 */
/** Standard Vigenère decrypt A–Z: P = (C − K) mod 26. */
export declare function vigenereDecryptA26(cipher: string, key: string): string;
/** Beaufort A–Z: P = (K − C) mod 26 (same family as community “Beaufort” on BO3 ciphers). */
export declare function beaufortDecryptA26(cipher: string, key: string): string;
/** 52-letter alphabet A–Z then a–z (common in Zombies Revelations–style tooling). */
export declare function vigenereDecryptA52(cipher: string, key: string): string;
export declare function beaufortDecryptA52(cipher: string, key: string): string;
export declare function atbashLettersA26(text: string): string;
/** Caesar on A–Z / a–z only. */
export declare function caesarDecryptA26(text: string, shift: number): string;
/** ROT13 convenience. */
export declare function rot13A26(text: string): string;
/**
 * Rail fence decode: ciphertext was produced by reading the zigzag row-by-row.
 */
export declare function railFenceDecode(ciphertext: string, numRails: number): string;
