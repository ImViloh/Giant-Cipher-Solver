import type { ReadabilityReport } from "./englishReadability.js";
import type { Candidate } from "./solver.js";
/**
 * Heuristic 0–100: not a statistical "probability" — label as plausibility in UI.
 */
export declare function estimatePlausibilityPercent(solved: boolean, readability: ReadabilityReport | undefined, nearMiss: Candidate | undefined): number;
/** Candidates that look less bad than typical noise (heuristic score floor). */
export declare function countPlausibleCandidates(candidates: Candidate[], scoreFloor?: number): number;
/** Count candidates in the “top tier” (within `delta` of the best heuristic score). */
export declare function countPossibleMatchesTopTier(candidates: Candidate[], deltaFromBest?: number): number;
export interface CandidatePoolStats {
    total: number;
    bestScore: number;
    worstScore: number;
    scoreSpread: number;
    avgTop5Score: number;
    medianScore: number;
    topTierCount: number;
    plausibleCount: number;
    /** Most common transform labels (method), for the overview table. */
    topMethods: {
        method: string;
        count: number;
    }[];
}
/**
 * Assumes `candidates` are sorted by descending heuristic score (as from `dedupeAndSort`).
 */
export declare function summarizeCandidatePool(candidates: Candidate[], topTierDelta?: number, plausibleFloor?: number): CandidatePoolStats;
