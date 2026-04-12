import type { Candidate } from "./solver.js";
/**
 * Second-stage transforms on the Base64-decoded payload: nested Base64, zlib,
 * hex, nibble swap, then XOR / RC4 with an expanded key list.
 * Bounded by env (see GIANT_LAYER_*).
 */
export declare function collectLayeredCandidates(decoded: Buffer): Candidate[];
