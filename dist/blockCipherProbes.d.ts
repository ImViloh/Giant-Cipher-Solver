export interface BlockProbeHit {
    algorithm: string;
    password: string;
    derivation: string;
    plain: Buffer;
}
/**
 * Try OpenSSL block ciphers that appear in community Zombies solves (AES-*, 3DES).
 * RC2 is attempted only if the runtime’s OpenSSL exposes it (often requires legacy provider).
 */
export declare function probeBlockCiphers(ciphertext: Buffer, passwords: string[], maxHits?: number): BlockProbeHit[];
/** Same probes with ciphertext bytes reversed first (common final-layer trick in Zombies ciphers). */
export declare function probeBlockCiphersReversedInput(decoded: Buffer, passwords: string[], maxHits?: number): BlockProbeHit[];
