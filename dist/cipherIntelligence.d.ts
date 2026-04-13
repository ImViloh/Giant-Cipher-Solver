/**
 * Aggregated cryptanalysis: statistics, per-family cipher likelihoods,
 * multi-layer hypotheses, and falsifiable critical notes — complements
 * payloadAnalysis + solver heuristics.
 */
import type { Candidate } from "./solver.js";
import type { PayloadAnalysisReport } from "./payloadAnalysis.js";
export interface CipherTypePrediction {
    id: string;
    label: string;
    /** 0–100 heuristic confidence (not statistical p-value). */
    confidence: number;
    summary: string;
    evidence: string[];
}
export interface LayerHypothesis {
    rank: number;
    /** Human-readable stack, outer → inner. */
    chain: string[];
    confidence: number;
    notes: string;
}
export interface CriticalInsight {
    title: string;
    observation: string;
    interpretation: string;
    falsify: string;
}
export interface CipherIntelligenceStats {
    indexOfCoincidence: number | null;
    letterCountForIoc: number;
    englishExpectedIoc: number;
    byteEntropyBits: number;
    printableAsciiRatio: number;
    zlibInflateLikely: boolean;
    zlibSizeRatio: number | null;
    approxPeriodFromStructure: number | null;
    topSolverMethods: {
        method: string;
        count: number;
    }[];
    bestCandidateMethod: string | null;
    bestCandidateScore: number | null;
}
export interface CipherIntelligenceReport {
    predictions: CipherTypePrediction[];
    layerHypotheses: LayerHypothesis[];
    insights: CriticalInsight[];
    stats: CipherIntelligenceStats;
}
/**
 * Build full intelligence report from outer Base64, decoded bytes, payload scan, and candidate pool.
 */
export declare function buildCipherIntelligence(opts: {
    outerBase64: string;
    decoded: Buffer | null;
    payload: PayloadAnalysisReport | null;
    candidates: Candidate[];
    solved: boolean;
}): CipherIntelligenceReport;
/** Plain text for session log. */
export declare function formatCipherIntelligenceForLog(report: CipherIntelligenceReport): string;
