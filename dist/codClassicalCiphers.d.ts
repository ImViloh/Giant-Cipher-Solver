/**
 * Classical ciphers documented across Treyarch Zombies / COD cipher hunts
 * (Base64/hex/Vigenère/XOR are elsewhere). Affine, Playfair, Bifid, columnar
 * transposition, keyed Caesar, and custom-alphabet Vigenère appear on maps such as
 * Classified, Der Eisendrache, Zetsubou No Shima, etc.
 */
/** Modular inverse of a mod 26; null if none (a must be coprime to 26). */
export declare function modInv26(a: number): number | null;
/** Valid multipliers a mod 26 (coprime to 26). */
export declare const AFFINE_A_VALUES: number[];
/** Affine decrypt: P = a⁻¹(C − b) mod 26 on A–Z; other chars unchanged. */
export declare function affineDecryptA26(ciphertext: string, a: number, b: number): string;
/** Playfair decrypt (5×5, I/J merged). Ciphertext digraphs; ignores non-letters. */
export declare function playfairDecrypt(ciphertext: string, keyword: string): string;
/**
 * Bifid decrypt (full-period): each ciphertext letter is a Polybius cell; the 2n coordinates
 * split into plaintext row coords (first n) and column coords (last n).
 */
export declare function bifidDecrypt(ciphertext: string, keyword: string): string;
/** Columnar transposition decrypt (keyword sorts column read order). */
export declare function columnarTranspositionDecrypt(ciphertext: string, keyword: string): string;
/** Keyed substitution alphabet from phrase, then Caesar shift on that alphabet. */
export declare function keyedCaesarDecrypt(ciphertext: string, keyPhrase: string, shift: number): string;
/** Vigenère where indices use a custom A–Z permutation (26 distinct letters). */
export declare function vigenereDecryptCustomAlphabet(ciphertext: string, key: string, alphabet: string): string;
/** Zetsubou No Shima cipher #11 — custom alphabet + keyword shinonuma (community solve). */
export declare const COD_CUSTOM_ALPHABET_ZNS = "AMUNOIHSZYXWVTRQPLKJGFEDCB";
