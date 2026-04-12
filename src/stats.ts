import type { ReadabilityReport } from "./englishReadability.js";
import { englishReadabilityRank } from "./englishReadability.js";
import type { Candidate } from "./solver.js";

/**
 * Heuristic 0–100: not a statistical "probability" — label as plausibility in UI.
 */
export function estimatePlausibilityPercent(
  solved: boolean,
  readability: ReadabilityReport | undefined,
  nearMiss: Candidate | undefined,
): number {
  if (solved) return 100;
  if (readability && readability.passes) return 100;

  const base = nearMiss
    ? englishReadabilityRank(nearMiss.text)
    : -200;

  if (!readability && nearMiss) {
    const r = Math.round(Math.min(92, Math.max(0, 35 + base / 6)));
    return r;
  }

  if (!readability) {
    return Math.round(Math.min(85, Math.max(0, 20 + base / 8)));
  }

  const r = readability;
  const ascii = r.asciiRatio * 28;
  const letters = r.letterRatio * 22;
  const dict = Math.min(32, r.dictWordHits * 2.2 + r.dictWordRatio * 40);
  const chi = Math.max(0, 18 - r.chiSq / 55);
  const quad = Math.min(12, r.quadgramHits * 400);
  return Math.round(Math.min(95, Math.max(0, ascii + letters + dict + chi + quad)));
}

/** Candidates that look less bad than typical noise (heuristic score floor). */
export function countPlausibleCandidates(
  candidates: Candidate[],
  scoreFloor = -35,
): number {
  return candidates.filter((c) => c.score >= scoreFloor).length;
}

/** Count candidates in the “top tier” (within `delta` of the best heuristic score). */
export function countPossibleMatchesTopTier(
  candidates: Candidate[],
  deltaFromBest = 25,
): number {
  if (candidates.length === 0) return 0;
  const best = candidates[0]!.score;
  return candidates.filter((c) => c.score >= best - deltaFromBest).length;
}

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
  topMethods: { method: string; count: number }[];
}

/**
 * Assumes `candidates` are sorted by descending heuristic score (as from `dedupeAndSort`).
 */
export function summarizeCandidatePool(
  candidates: Candidate[],
  topTierDelta = 25,
  plausibleFloor = -35,
): CandidatePoolStats {
  const n = candidates.length;
  if (n === 0) {
    return {
      total: 0,
      bestScore: 0,
      worstScore: 0,
      scoreSpread: 0,
      avgTop5Score: 0,
      medianScore: 0,
      topTierCount: 0,
      plausibleCount: 0,
      topMethods: [],
    };
  }

  const scores = candidates.map((c) => c.score);
  const best = scores[0]!;
  const worst = scores[n - 1]!;
  const top5 = scores.slice(0, Math.min(5, n));
  const avgTop5 = top5.reduce((a, b) => a + b, 0) / top5.length;
  const median = scores[Math.floor(n / 2)]!;

  const byMethod = new Map<string, number>();
  for (const c of candidates) {
    byMethod.set(c.method, (byMethod.get(c.method) ?? 0) + 1);
  }
  const topMethods = [...byMethod.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([method, count]) => ({ method, count }));

  return {
    total: n,
    bestScore: best,
    worstScore: worst,
    scoreSpread: best - worst,
    avgTop5Score: avgTop5,
    medianScore: median,
    topTierCount: countPossibleMatchesTopTier(candidates, topTierDelta),
    plausibleCount: countPlausibleCandidates(candidates, plausibleFloor),
    topMethods,
  };
}
