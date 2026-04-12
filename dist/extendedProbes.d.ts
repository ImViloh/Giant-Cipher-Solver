import type { Candidate } from "./solver.js";
/**
 * Classical letter ciphers, OpenSSL block tries (AES / 3DES / RC2* / BF*), and reversed-input variants.
 * Disable entirely with `GIANT_EXTENDED_PROBES=0`.
 */
export declare function collectExtendedProbeCandidates(decoded: Buffer): Candidate[];
