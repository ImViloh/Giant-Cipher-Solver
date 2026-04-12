import type { ReadabilityReport } from "./englishReadability.js";
import type { CandidatePoolStats } from "./stats.js";
import type { WordHit } from "./wordScan.js";
import type { Candidate } from "./solver.js";
/** Opening hero + subtitle. */
export declare function renderHero(solved: boolean): void;
export declare function renderInputStrip(opts: {
    inputPath: string;
    base64Length: number;
}): void;
/** Legacy --dump-all mode header. */
export declare function renderDumpIntro(opts: {
    inputPath: string;
    base64Length: number;
    totalCandidates: number;
    afterFilter: number;
}): void;
export interface DashboardOpts {
    elapsedMs: number;
    plausibilityPercent: number;
    solved: boolean;
    pool: CandidatePoolStats;
    xorTried: number;
    vigTried: number;
    xorTimeout: boolean;
    vigTimeout: boolean;
    topTierDelta: number;
    plausibleFloor: number;
}
export declare function renderStatsDashboard(o: DashboardOpts): void;
export declare function renderPhasesPipeline(phases: string[]): void;
export declare function renderWordHits(hits: WordHit[], maxShow?: number): void;
export declare function renderLogFooter(path: string): void;
export declare function renderOutcomeBanner(solved: boolean): void;
export declare function renderCandidateCard(c: Candidate, title: string): void;
export declare function renderReadabilityCard(r: ReadabilityReport): void;
export declare const banner: (title: string) => void;
export declare const section: (title: string) => void;
export declare const kv: (key: string, value: string, valueColor?: (s: string) => string) => void;
export declare function statsBlock(opts: DashboardOpts): void;
export declare const phasesRow: typeof renderPhasesPipeline;
export declare const wordHitsConsole: typeof renderWordHits;
export declare const candidateBlock: typeof renderCandidateCard;
export declare const readabilityBlock: typeof renderReadabilityCard;
export declare const solvedBanner: () => void;
export declare const unsolvedBanner: () => void;
export declare const logFileNote: typeof renderLogFooter;
