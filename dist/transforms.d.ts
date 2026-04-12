/** Standard Base64 alphabet order (RFC 4648). */
export declare const B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
export declare function safeBase64Decode(s: string): Buffer | null;
/** Vigenère decrypt on Base64 alphabet: P = (C - K) mod 64 */
export declare function vigenereBase64Decrypt(cipherB64: string, key: string): string;
/** Beaufort variant on Base64: P = (K - C) mod 64 */
export declare function beaufortBase64Decrypt(cipherB64: string, key: string): string;
/** Atbash on Base64 alphabet: index i → 63 − i */
export declare function atbashBase64(cipherB64: string): string;
export declare function rotateBase64Alphabet(cipherB64: string, r: number): string;
export declare function xorBuffer(buf: Buffer, key: string | Buffer | Uint8Array): Buffer;
export declare function xorSingleByte(buf: Buffer, b: number): Buffer;
export declare function reverseBuffer(buf: Buffer): Buffer;
export declare function builtinXorKeys(): string[];
/**
 * Keywords tied to Treyarch Zombies / Jason Blundell-era cipher hunts (Revelations, The Giant, etc.).
 * Used for classical polyalphabetic probes and block-cipher passphrases (mcrypt-style tooling).
 */
export declare function blundellCipherKeywords(): string[];
export declare function md5Hex(s: string): string;
/** Short keys from hashing common phrases (hex bytes used as XOR key). */
export declare function derivedKeys(): string[];
/** SHA256-derived hex keys (16 hex chars = 8 bytes as XOR/RC4 material). */
export declare function derivedSha256Keys(): string[];
/**
 * Lore + hash-derived keys for repeating XOR, Vigenère, and layered RC4.
 * Deduplicated; use with `GIANT_EXTRA_KEYS` (env) in the solver.
 */
export declare function allStretchXorKeys(): string[];
