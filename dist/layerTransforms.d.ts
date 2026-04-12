/** RC4 keystream XOR (common in games / custom crypto). */
export declare function rc4Transform(data: Buffer, key: Buffer): Buffer;
export declare function tryZlibVariants(buf: Buffer): Buffer | null;
/** Whether buffer looks like a Base64 text payload (second layer). */
export declare function looksLikeBase64Text(buf: Buffer): boolean;
export interface LayerBuf {
    buf: Buffer;
    /** Human-readable transform chain */
    path: string;
}
/**
 * Unwrap nested Base64 (decode until not b64-like or max depth).
 */
export declare function collectNestedBase64(first: Buffer, maxDepth: number): LayerBuf[];
export declare function tryHexAsciiDecode(buf: Buffer): Buffer | null;
export declare function bufHashShort(buf: Buffer): string;
export declare function swapNibbles(buf: Buffer): Buffer;
/** If data was produced as c[i] = p[i] ⊕ c[i−1], recover p by unrolling from the end. */
export declare function decodeCumulativeXor(buf: Buffer): Buffer;
export declare function looksLikeHexAscii(buf: Buffer): boolean;
